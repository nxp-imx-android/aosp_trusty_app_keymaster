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

#include <uapi/err.h>

#ifndef DISABLE_ATAP_SUPPORT
#include <libatap/libatap.h>
// This assumes EC cert chains do not exceed 1k and other cert chains do not
// exceed 5k.
const size_t kMaxCaResponseSize = 20000;
#endif

namespace keymaster {

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
}  // namespace keymaster
