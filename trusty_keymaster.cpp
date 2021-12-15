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

#include <lib/keybox/client/keybox.h>
#include <uapi/err.h>

#include <memory>

#ifndef DISABLE_ATAP_SUPPORT
#include <libatap/libatap.h>
// This assumes EC cert chains do not exceed 1k and other cert chains do not
// exceed 5k.
const size_t kMaxCaResponseSize = 20000;
#endif

namespace keymaster {

GetVersion2Response TrustyKeymaster::GetVersion2(
        const GetVersion2Request& req) {
    switch (req.max_message_version) {
    case 3:
        context_->SetKmVersion(KmVersion::KEYMASTER_4);
        break;

    case 4:
        context_->SetKmVersion(KmVersion::KEYMINT_2);
        break;

    default:
        LOG_E("HAL sent invalid message version %d, crashing",
              req.max_message_version);
        abort();
    }

    return AndroidKeymaster::GetVersion2(req);
}

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

AttestationKeySlot keymaster_algorithm_to_key_slot(
        keymaster_algorithm_t algorithm) {
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return AttestationKeySlot::kRsa;
    case KM_ALGORITHM_EC:
        return AttestationKeySlot::kEcdsa;
    default:
        return AttestationKeySlot::kInvalid;
    }
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

    key_slot = keymaster_algorithm_to_key_slot(request.algorithm);
    if (key_slot == AttestationKeySlot::kInvalid) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
    if (key_size == 0) {
        response->error = KM_ERROR_INVALID_INPUT_LENGTH;
        return;
    }
    response->error = ss_manager->WriteKeyToStorage(key_slot, key, key_size);
}

void TrustyKeymaster::SetAttestationIds(const SetAttestationIdsRequest& request,
                                        EmptyKeymasterResponse* response) {
    if (response == nullptr) {
        return;
    }
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }
    response->error = ss_manager->SetAttestationIds(request);
}

void TrustyKeymaster::SetWrappedAttestationKey(
        const SetAttestationKeyRequest& request,
        SetAttestationKeyResponse* response) {
    if (response == nullptr) {
        return;
    }
    AttestationKeySlot key_slot =
            keymaster_algorithm_to_key_slot(request.algorithm);
    if (key_slot == AttestationKeySlot::kInvalid) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
    /*
     * This assumes unwrapping decreases size.
     * If it doesn't, the unwrap call will fail.
     */
    size_t unwrapped_buf_size = request.key_data.buffer_size();
    size_t unwrapped_key_size;
    std::unique_ptr<uint8_t[]> unwrapped_key(new uint8_t[unwrapped_buf_size]);
    if (!unwrapped_key) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }
    int rc = keybox_unwrap(request.key_data.begin(),
                           request.key_data.buffer_size(), unwrapped_key.get(),
                           unwrapped_buf_size, &unwrapped_key_size);
    if (rc != NO_ERROR) {
        response->error = KM_ERROR_VERIFICATION_FAILED;
        return;
    }

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    response->error = ss_manager->WriteKeyToStorage(
            key_slot, unwrapped_key.get(), unwrapped_key_size);
}

void TrustyKeymaster::ClearAttestationCertChain(
        const ClearAttestationCertChainRequest& request,
        ClearAttestationCertChainResponse* response) {
    if (response == nullptr)
        return;

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        response->error = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
        return;
    }

    AttestationKeySlot key_slot;

    key_slot = keymaster_algorithm_to_key_slot(request.algorithm);
    if (key_slot == AttestationKeySlot::kInvalid) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }

    keymaster_error_t err = ss_manager->DeleteCertChainFromStorage(key_slot);
    if (err != KM_ERROR_OK) {
        LOG_E("Failed to delete cert chain.\n", 0);
        response->error = err;
        return;
    }

    uint32_t cert_chain_length = 0;
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

    response->error = KM_ERROR_OK;
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
}  // namespace keymaster
