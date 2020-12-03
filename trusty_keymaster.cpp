/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "trusty_keymaster.h"
#include "secure_storage_manager.h"
#include <string.h>

#include <lib/hwkey/hwkey.h>
#include <uapi/err.h>
#include <openssl/sha.h>

#ifndef DISABLE_ATAP_SUPPORT
#include <libatap/libatap.h>
// This assumes EC cert chains do not exceed 1k and other cert chains do not
// exceed 5k.
const size_t kMaxCaResponseSize = 20000;
#endif

namespace keymaster {

static const int kIDSizeMax = 2048;

long TrustyKeymaster::GetAuthTokenKey(keymaster_key_blob_t* key) {
    keymaster_error_t error = context_->GetAuthTokenKey(key);
    if (error != KM_ERROR_OK)
        return ERR_GENERIC;
    return NO_ERROR;
}

void TrustyKeymaster::SetBootParams(const SetBootParamsRequest& request,
                                    SetBootParamsResponse* response) {
    if (response == nullptr)
        return;

    response->error = context_->SetBootParams(
            request.os_version, request.os_patchlevel,
            request.verified_boot_key, request.verified_boot_state,
            request.device_locked, request.verified_boot_hash);
}

void TrustyKeymaster::SetAttestationKey_enc(const SetAttestationKeyRequest& request,
                                        SetAttestationKeyResponse* response) {
    uint8_t out[2048] = {0};
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    size_t key_size = request.key_data.buffer_size();
    const uint8_t* enckey = request.key_data.begin();
    struct attestation_blob_header *header = (struct attestation_blob_header*)enckey;
    uint8_t *in = (uint8_t*)(enckey+ sizeof(struct attestation_blob_header));

    if (strcmp(header->magic, BLOB_HEADER_MAGIC)) {
        response->error = KM_ERROR_INCOMPATIBLE_KEY_FORMAT;
        return;
    }

    if (key_size <= sizeof(struct attestation_blob_header)) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }

    long rc = hwkey_open();
    if (rc < 0) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    hwkey_session_t session = (hwkey_session_t)rc;

    rc = hwkey_mp_decrypt(session, in, key_size - sizeof(struct attestation_blob_header), out);

    hwkey_close(session);
    AttestationKeySlot key_slot;

    switch (request.algorithm) {
    case KM_ALGORITHM_RSA:
        key_slot = AttestationKeySlot::kRsa;
        break;
    case KM_ALGORITHM_EC:
        key_slot = AttestationKeySlot::kEcdsa;
        break;
    default:
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
    if (key_size == 0) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }

    response->error = ss_manager->WriteKeyToStorage(key_slot, out, header->len);

}

void TrustyKeymaster::SetAttestationKey(const SetAttestationKeyRequest& request,
                                        SetAttestationKeyResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    size_t key_size = request.key_data.buffer_size();
    const uint8_t* key = request.key_data.begin();
    AttestationKeySlot key_slot;

    switch (request.algorithm) {
    case KM_ALGORITHM_RSA:
        key_slot = AttestationKeySlot::kRsa;
        break;
    case KM_ALGORITHM_EC:
        key_slot = AttestationKeySlot::kEcdsa;
        break;
    default:
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
    if (key_size == 0) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }
    response->error = ss_manager->WriteKeyToStorage(key_slot, key, key_size);
}

void TrustyKeymaster::GetMppubk(const GetMppubkRequest& request,
                                        GetMppubkResponse* response) {
    uint8_t key[64];
    uint32_t key_size = 64;
    const char* mppubk_key_id = "com.android.trusty.keymaster.mppubk";

    if (response == nullptr)
        return;

    long rc = hwkey_open();
    if (rc < 0) {
        response->error = KM_ERROR_UNKNOWN_ERROR;
        return;
    }

    hwkey_session_t session = (hwkey_session_t)rc;
    /* Generate manufacture production public key */
    rc = hwkey_get_keyslot_data(session, mppubk_key_id, key, &key_size);
    if (rc < 0) {
        response->error = KM_ERROR_UNKNOWN_ERROR;
        return;
    }
    hwkey_close(session);

    response->data.Reinitialize(key, key_size);
    response->error = KM_ERROR_OK;
}

void TrustyKeymaster::VerifySecureUnlock(const VerifySecureUnlockRequest& request,
                                         VerifySecureUnlockResponse* response) {

    uint8_t out_buf[32] = {0};
    uint32_t credential_size = request.credential_data.buffer_size();
    uint32_t serial_size = request.serial_data.buffer_size();
    uint8_t *credential, *in_ptr;

    credential = (uint8_t *)(request.credential_data.begin());
    in_ptr = (uint8_t*)(credential + sizeof(struct attestation_blob_header));

    /* Check the magic head. */
    if (strcmp(((struct attestation_blob_header *)credential)->magic, BLOB_HEADER_MAGIC)) {
        response->error = KM_ERROR_INCOMPATIBLE_KEY_FORMAT;
        return;
    }
    if (credential_size <= sizeof(struct attestation_blob_header)) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }
    int rc = hwkey_open();
    if (rc < 0) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    hwkey_session_t session = (hwkey_session_t)rc;

    /* Decrypt the serial number */
    rc = hwkey_mp_decrypt(session, in_ptr,
                          credential_size - sizeof(struct attestation_blob_header), out_buf);

    hwkey_close(session);

    /* Verify the serial number, return error if verify fail. */
    if (serial_size > 32) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }

    if (memcmp(out_buf, request.serial_data.begin(), serial_size)) {
        LOG_E("secure unlock credential verify fail!\n", 0);
        response->error = KM_ERROR_UNKNOWN_ERROR;
    } else {
        response->error = KM_ERROR_OK;
    }

}

void TrustyKeymaster::AppendAttestationCertChain_enc(
        const AppendAttestationCertChainRequest& request,
        AppendAttestationCertChainResponse* response) {

    uint8_t out[2048] = {0};
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }


    size_t cert_size = request.cert_data.buffer_size();
    const uint8_t* blob= request.cert_data.begin();
    struct attestation_blob_header *header = (struct attestation_blob_header*)blob;
    uint8_t *in = (uint8_t*)(blob + sizeof(struct attestation_blob_header));

    if (strcmp(header->magic, BLOB_HEADER_MAGIC)) {
        response->error = KM_ERROR_INCOMPATIBLE_KEY_FORMAT;
        return;
    }

    if (cert_size <= sizeof(struct attestation_blob_header)) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }

    long rc = hwkey_open();
    if (rc < 0) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    hwkey_session_t session = (hwkey_session_t)rc;
    rc = hwkey_mp_decrypt(session, in, cert_size - sizeof(struct attestation_blob_header), out);

    hwkey_close(session);
    AttestationKeySlot key_slot;

    response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    switch (request.algorithm) {
    case KM_ALGORITHM_RSA:
        key_slot = AttestationKeySlot::kRsa;
        break;
    case KM_ALGORITHM_EC:
        key_slot = AttestationKeySlot::kEcdsa;
        break;
    default:
        return;
    }
    response->error = KM_ERROR_INVALID_INPUT_LENGTH;
    if (cert_size == 0) {
        return;
    }
    uint32_t cert_chain_length = 0;
    if (ss_manager->ReadCertChainLength(key_slot, &cert_chain_length) !=
        KM_ERROR_OK) {
        LOG_E("Failed to read cert chain length, initialize to 0.\n", 0);
        cert_chain_length = 0;
    }
    if (cert_chain_length >= kMaxCertChainLength) {
        // Delete the cert chain when it hits max length.
        keymaster_error_t err =
                ss_manager->DeleteCertChainFromStorage(key_slot);
        if (err != KM_ERROR_OK) {
            LOG_E("Failed to delete cert chain.\n", 0);
            response->error = err;
            return;
        }
        err = ss_manager->ReadCertChainLength(key_slot, &cert_chain_length);
        if (err != KM_ERROR_OK) {
            LOG_E("Failed to read cert chain length.\n", 0);
            response->error = err;
            return;
        }
        if (cert_chain_length != 0) {
            LOG_E("Cert chain could not be deleted.\n", 0);
            response->error = err;
            return;
        }
    }
    response->error = ss_manager->WriteCertToStorage(key_slot, out, header->len,
                                                     cert_chain_length);
}

void TrustyKeymaster::AppendAttestationCertChain(
        const AppendAttestationCertChainRequest& request,
        AppendAttestationCertChainResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    size_t cert_size = request.cert_data.buffer_size();
    const uint8_t* cert = request.cert_data.begin();
    AttestationKeySlot key_slot;

    response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    switch (request.algorithm) {
    case KM_ALGORITHM_RSA:
        key_slot = AttestationKeySlot::kRsa;
        break;
    case KM_ALGORITHM_EC:
        key_slot = AttestationKeySlot::kEcdsa;
        break;
    default:
        return;
    }
    response->error = KM_ERROR_INVALID_INPUT_LENGTH;
    if (cert_size == 0) {
        return;
    }
    uint32_t cert_chain_length = 0;
    if (ss_manager->ReadCertChainLength(key_slot, &cert_chain_length) !=
        KM_ERROR_OK) {
        LOG_E("Failed to read cert chain length, initialize to 0.\n", 0);
        cert_chain_length = 0;
    }
    if (cert_chain_length >= kMaxCertChainLength) {
        // Delete the cert chain when it hits max length.
        keymaster_error_t err =
                ss_manager->DeleteCertChainFromStorage(key_slot);
        if (err != KM_ERROR_OK) {
            LOG_E("Failed to delete cert chain.\n", 0);
            response->error = err;
            return;
        }
        err = ss_manager->ReadCertChainLength(key_slot, &cert_chain_length);
        if (err != KM_ERROR_OK) {
            LOG_E("Failed to read cert chain length.\n", 0);
            response->error = err;
            return;
        }
        if (cert_chain_length != 0) {
            LOG_E("Cert chain could not be deleted.\n", 0);
            response->error = err;
            return;
        }
    }
    response->error = ss_manager->WriteCertToStorage(key_slot, cert, cert_size,
                                                     cert_chain_length);
}

void TrustyKeymaster::AtapGetCaRequest(const AtapGetCaRequestRequest& request,
                                       AtapGetCaRequestResponse* response) {
    if (response == nullptr)
        return;

#ifdef DISABLE_ATAP_SUPPORT
    // Not implemented.
    response->error = KM_ERROR_UNKNOWN_ERROR;
    return;
#else
    uint8_t* ca_request;
    uint32_t ca_request_size;
    const Buffer& operation_start = request.data;
    AtapResult result = atap_get_ca_request(
            atap_ops_provider_.atap_ops(), operation_start.begin(),
            operation_start.available_read(), &ca_request, &ca_request_size);
    response->error = KM_ERROR_UNKNOWN_ERROR;
    if (result != ATAP_RESULT_OK) {
        return;
    }
    response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (!response->data.Reinitialize(ca_request, ca_request_size)) {
        atap_free(ca_request);
        return;
    }
    atap_free(ca_request);
    response->error = KM_ERROR_OK;
#endif
}

void TrustyKeymaster::AtapSetCaResponseBegin(
        const AtapSetCaResponseBeginRequest& request,
        AtapSetCaResponseBeginResponse* response) {
    if (response == nullptr)
        return;

#ifdef DISABLE_ATAP_SUPPORT
    // Not implemented.
    response->error = KM_ERROR_UNKNOWN_ERROR;
    return;
#else
    response->error = KM_ERROR_INVALID_ARGUMENT;
    if (request.ca_response_size > kMaxCaResponseSize) {
        return;
    }
    response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (!ca_response_.reserve(request.ca_response_size)) {
        return;
    }
    response->error = KM_ERROR_OK;
#endif
}

void TrustyKeymaster::AtapSetCaResponseUpdate(
        const AtapSetCaResponseUpdateRequest& request,
        AtapSetCaResponseUpdateResponse* response) {
    if (response == nullptr)
        return;

#ifdef DISABLE_ATAP_SUPPORT
    // Not implemented.
    response->error = KM_ERROR_UNKNOWN_ERROR;
    return;
#else
    response->error = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
    if (!ca_response_.write(request.data.begin(), request.data.buffer_size())) {
        return;
    }
    response->error = KM_ERROR_OK;
#endif
}

void TrustyKeymaster::AtapSetCaResponseFinish(
        const AtapSetCaResponseFinishRequest& request,
        AtapSetCaResponseFinishResponse* response) {
    if (response == nullptr)
        return;

#ifdef DISABLE_ATAP_SUPPORT
    // Not implemented.
    response->error = KM_ERROR_UNKNOWN_ERROR;
    return;
#else
    response->error = KM_ERROR_INVALID_INPUT_LENGTH;
    if (ca_response_.available_read() != ca_response_.buffer_size()) {
        LOG_E("Did not receive full CA Response message: %d / %d\n",
              ca_response_.available_read(), ca_response_.buffer_size());
        return;
    }
    response->error = KM_ERROR_UNKNOWN_ERROR;
    AtapResult result = atap_set_ca_response(atap_ops_provider_.atap_ops(),
                                             ca_response_.begin(),
                                             ca_response_.available_read());
    if (result == ATAP_RESULT_OK) {
        response->error = KM_ERROR_OK;
    }
    ca_response_.Clear();
#endif
}

void TrustyKeymaster::AtapReadUuid(const AtapReadUuidRequest& request,
                                   AtapReadUuidResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    uint8_t uuid[kAttestationUuidSize]{};
    response->error = ss_manager->ReadAttestationUuid(uuid);

    if (response->error == KM_ERROR_OK) {
        response->data.reserve(kAttestationUuidSize);
        response->data.write(uuid, kAttestationUuidSize);
    }
}

void TrustyKeymaster::AtapSetProductId(const AtapSetProductIdRequest& request,
                                       AtapSetProductIdResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

#ifdef DISABLE_ATAP_SUPPORT
    // Not implemented.
    response->error = KM_ERROR_UNKNOWN_ERROR;
    return;
#else
    response->error = KM_ERROR_UNKNOWN_ERROR;
    const Buffer& product_id = request.data;
    uint32_t product_id_size = product_id.available_read();
    if (product_id_size != kProductIdSize) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }
    response->error = ss_manager->SetProductId(product_id.begin());
#endif
}

void TrustyKeymaster::DestroyAttestationIds(const DestroyAttestationIdsRequest& request,
                                       DestroyAttestationIdsResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->error = ss_manager->DeleteAttestationID(true);
}

void TrustyKeymaster::AppendAttestationId(
        const AppendAttestationIdRequest& request,
        AppendAttestationIdResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    const uint8_t* id = request.id_data.begin();
    size_t id_size = request.id_data.buffer_size();
    if (id_size == 0) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }

    // Load hardware bound key
    uint8_t hbk[kHardwareBoundKeySize];
    uint32_t hbk_size = kHardwareBoundKeySize;
    keymaster_error_t err = context_->LoadHbk(hbk, &hbk_size);
    if (err != KM_ERROR_OK) {
        LOG_E("Error: failed to load hardward bound key, err: %d\n", err);
        response->error = err;
        return;
    }

    // Read Device IDs in storage
    AttestationID* attestation_id_p;
    err = ss_manager->ReadAttestationID(&attestation_id_p);
    if (err != KM_ERROR_OK) {
        response->error = err;
        return;
    }

    KeymasterBlob hmac_out;
    keymaster_blob_t data;
    keymaster_blob_t data_chunks[1];
    keymaster_key_blob_t hmac_key = {
            reinterpret_cast<const uint8_t*>(hbk),
            kHardwareBoundKeySize};
    // Sanity check the loaded IDs
    UniquePtr<AttestationID> attestation_id(attestation_id_p);
    if (attestation_id->has_hmac_all || attestation_id->has_hmac_id) {
        // hmac_all should be HMAC(HBK, hmac_id)
        data.data = reinterpret_cast<const uint8_t*>(attestation_id->hmac_id.bytes);
        data.data_length = attestation_id->hmac_id.size;
        data_chunks[0] = data;
        err = OpenSSLKeymasterEnforcement::hmacSha256(hmac_key, data_chunks, 1, &hmac_out);
        if (err != KM_ERROR_OK) {
            LOG_E("Error: failed to compute hmacsha256 for device ID, err: %d\n", err);
            response->error = err;
            return;
        }

        if (memcmp(hmac_out.data, attestation_id->hmac_all.bytes, SHA256_DIGEST_LENGTH)) {
            LOG_E("Error: Device ID was destoried!", 0);
            // Delete the device ID when error
            ss_manager->DeleteAttestationID(true);
            response->error = KM_ERROR_CANNOT_ATTEST_IDS;
            return;
        }
    }

    if (attestation_id->hmac_id.size + SHA256_DIGEST_LENGTH > kIDSizeMax) {
        LOG_E("Error: Device IDs hamc exceeds the limit!\n", 0);
        response->error = KM_ERROR_CANNOT_ATTEST_IDS;
        return;
    }

    // Compute the hmacsha256 of input ID
    data.data = reinterpret_cast<const uint8_t*>(id);
    data.data_length = id_size;
    data_chunks[0] = data;

    err = OpenSSLKeymasterEnforcement::hmacSha256(hmac_key, data_chunks, 1, &hmac_out);
    if (err != KM_ERROR_OK) {
        LOG_E("Error: failed to compute hmacsha256 for device ID, err: %d\n", err);
        response->error = err;
        return;
    }

    // Append id hmac, hmac_id = HMAC(HBK, ID1) || HMAC(HBK, ID2) || ... || HMAC(HBK, IDn)
    memcpy(attestation_id->hmac_id.bytes + attestation_id->hmac_id.size,
           hmac_out.data, SHA256_DIGEST_LENGTH);
    attestation_id->hmac_id.size += SHA256_DIGEST_LENGTH;

    // Update hmac_all, hmac_all = HMAC(HBK, hmac_id)
    data.data = reinterpret_cast<const uint8_t*>(attestation_id->hmac_id.bytes);
    data.data_length = attestation_id->hmac_id.size;
    data_chunks[0] = data;
    err = OpenSSLKeymasterEnforcement::hmacSha256(hmac_key, data_chunks, 1, &hmac_out);
    if (err != KM_ERROR_OK) {
        LOG_E("Error: failed to compute hmacsha256 for device IDs, err: %d\n", err);
        // Delete the device ID when error
        ss_manager->DeleteAttestationID(true);
        response->error = err;
        return;
    }
    memcpy(attestation_id->hmac_all.bytes, hmac_out.data, SHA256_DIGEST_LENGTH);
    attestation_id->hmac_all.size = SHA256_DIGEST_LENGTH;

    attestation_id->has_hmac_id  = true;
    attestation_id->has_hmac_all = true;

    response->error = ss_manager->WriteAttestationID(attestation_id.get(), true);
}

}  // namespace keymaster
