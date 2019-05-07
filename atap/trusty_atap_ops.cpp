/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "trusty_atap_ops.h"
#include "secure_storage_manager.h"
#include "trusty_logger.h"

#include <keymaster/UniquePtr.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace {

using keymaster::AttestationKeySlot;

AttestationKeySlot MapKeyTypeToSlot(const AtapKeyType atap_key_type) {
    switch (atap_key_type) {
    case ATAP_KEY_TYPE_RSA:
        return AttestationKeySlot::kRsa;
    case ATAP_KEY_TYPE_ECDSA:
        return AttestationKeySlot::kEcdsa;
    case ATAP_KEY_TYPE_edDSA:
        return AttestationKeySlot::kEddsa;
    case ATAP_KEY_TYPE_EPID:
        return AttestationKeySlot::kEpid;
    case ATAP_KEY_TYPE_SPECIAL:
        return AttestationKeySlot::kClaimable0;
    case ATAP_KEY_TYPE_RSA_SOM:
        return AttestationKeySlot::kSomRsa;
    case ATAP_KEY_TYPE_ECDSA_SOM:
        return AttestationKeySlot::kSomEcdsa;
    case ATAP_KEY_TYPE_edDSA_SOM:
        return AttestationKeySlot::kSomEddsa;
    case ATAP_KEY_TYPE_EPID_SOM:
        return AttestationKeySlot::kSomEpid;
    default:
        return AttestationKeySlot::kInvalid;
    }
    return AttestationKeySlot::kInvalid;
}

}  // namespace

namespace keymaster {

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

TrustyAtapOps::TrustyAtapOps() {}
TrustyAtapOps::~TrustyAtapOps() {}

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const {
        PKCS8_PRIV_KEY_INFO_free(p);
    }
};
typedef UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete>
        Unique_PKCS8_PRIV_KEY_INFO;
struct EVP_MD_CTX_Delete {
    void operator()(EVP_MD_CTX* p) const {
        EVP_MD_CTX_cleanup(p);
        EVP_MD_CTX_destroy(p);
    }
};
typedef UniquePtr<EVP_MD_CTX, EVP_MD_CTX_Delete> Unique_EVP_MD_CTX;

AtapResult TrustyAtapOps::read_product_id(
        uint8_t product_id[ATAP_PRODUCT_ID_LEN]) {
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr)
        return ATAP_RESULT_ERROR_STORAGE;
    if (ss_manager->ReadProductId(product_id) != KM_ERROR_OK) {
        /* If we can't get permanent attributes, set product id to the test
        product id (all zero). */
        LOG_E("Fail to read product id from storage, set as 0.", 0);
        memset(product_id, 0, ATAP_PRODUCT_ID_LEN);
    }
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::get_auth_key_type(AtapKeyType* key_type) {
    if (_auth_key_type_init) {
        *key_type = _auth_key_type;
        return ATAP_RESULT_OK;
    }
    *key_type = ATAP_KEY_TYPE_NONE;
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr)
        return ATAP_RESULT_ERROR_STORAGE;
    const AtapKeyType kAuthKeyTypes[3] = {ATAP_KEY_TYPE_EPID_SOM,
                                          ATAP_KEY_TYPE_RSA_SOM,
                                          ATAP_KEY_TYPE_ECDSA_SOM};

    for (size_t i = 0; i < (sizeof(kAuthKeyTypes) / sizeof(AtapKeyType)); i++) {
        AttestationKeySlot key_slot = MapKeyTypeToSlot(kAuthKeyTypes[i]);
        bool key_exists;
        if (ss_manager->AttestationKeyExists(key_slot, &key_exists) !=
            KM_ERROR_OK) {
            return ATAP_RESULT_ERROR_STORAGE;
        }
        if (key_exists) {
            *key_type = kAuthKeyTypes[i];
            break;
        }
    }

    _auth_key_type_init = true;
    _auth_key_type = *key_type;
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::read_auth_key_cert_chain(AtapCertChain* cert_chain) {
    AtapKeyType key_type;
    AtapResult atap_result = get_auth_key_type(&key_type);
    if (atap_result != ATAP_RESULT_OK) {
        LOG_E("Failed to get key type.", 0);
        return atap_result;
    }
    if (key_type == ATAP_KEY_TYPE_NONE) {
        return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
    }
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        return ATAP_RESULT_ERROR_STORAGE;
    }
    AttestationKeySlot key_slot = MapKeyTypeToSlot(key_type);
    keymaster_error_t result =
            ss_manager->ReadAtapCertChainFromStorage(key_slot, cert_chain);
    if (result != KM_ERROR_OK) {
        LOG_E("Failed to read som cert chain from slot %d (err = %d)", key_slot,
              result);
        return ATAP_RESULT_ERROR_STORAGE;
    }
    if (cert_chain->entry_count > ATAP_CERT_CHAIN_ENTRIES_MAX) {
        LOG_E("Stored cert chain length is larger than the maximum cert chain length",
              0);
        return ATAP_RESULT_ERROR_CRYPTO;
    }
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::write_attestation_key(
        AtapKeyType key_type,
        const AtapBlob* key,
        const AtapCertChain* cert_chain) {
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr)
        return ATAP_RESULT_ERROR_STORAGE;
    AttestationKeySlot slot = MapKeyTypeToSlot(key_type);
    if (key_type == ATAP_KEY_TYPE_RSA_SOM ||
        key_type == ATAP_KEY_TYPE_ECDSA_SOM ||
        key_type == ATAP_KEY_TYPE_EPID_SOM ||
        key_type == ATAP_KEY_TYPE_edDSA_SOM) {
        /* If writing a som key, invalidate the cached auth_key_type. */
        _auth_key_type_init = false;
    }
    if (slot == AttestationKeySlot::kInvalid) {
        return ATAP_RESULT_ERROR_INVALID_INPUT;
    }

    keymaster_error_t result = ss_manager->WriteAtapKeyAndCertsToStorage(
            slot, key->data, key->data_length, cert_chain);
    if (result != KM_ERROR_OK) {
        LOG_E("Failed to write key and certs to slot %d (err = %d)", slot,
              result);
        return ATAP_RESULT_ERROR_STORAGE;
    }
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::read_attestation_public_key(
        AtapKeyType key_type,
        uint8_t pubkey[ATAP_KEY_LEN_MAX],
        uint32_t* pubkey_len) {
    return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
}

AtapResult TrustyAtapOps::read_soc_global_key(
        uint8_t global_key[ATAP_AES_128_KEY_LEN]) {
    return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
}

AtapResult TrustyAtapOps::write_hex_uuid(
        const uint8_t uuid[ATAP_HEX_UUID_LEN]) {
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr)
        return ATAP_RESULT_ERROR_STORAGE;
    if (ss_manager->WriteAttestationUuid(uuid) != KM_ERROR_OK) {
        return ATAP_RESULT_ERROR_STORAGE;
    }
    return ATAP_RESULT_OK;
}

AtapResult TrustyAtapOps::auth_key_sign(const uint8_t* nonce,
                                        uint32_t nonce_len,
                                        uint8_t sig[ATAP_SIGNATURE_LEN_MAX],
                                        uint32_t* sig_len) {
    AtapKeyType key_type;
    keymaster_error_t result = KM_ERROR_OK;
    AtapResult atap_result = get_auth_key_type(&key_type);
    if (atap_result != ATAP_RESULT_OK) {
        LOG_E("Failed to get key type", 0);
        return atap_result;
    }
    if (key_type == ATAP_KEY_TYPE_NONE) {
        return ATAP_RESULT_ERROR_UNSUPPORTED_OPERATION;
    }
    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        return ATAP_RESULT_ERROR_STORAGE;
    }
    AttestationKeySlot key_slot = MapKeyTypeToSlot(key_type);

    KeymasterKeyBlob key_blob =
            ss_manager->ReadKeyFromStorage(key_slot, &result);
    if (result != KM_ERROR_OK) {
        LOG_E("Failed to read som cert chain from slot %d (err = %d)", key_slot,
              result);
        return ATAP_RESULT_ERROR_STORAGE;
    }

    const uint8_t* pkcs_priv_key_p = key_blob.key_material;

    Unique_PKCS8_PRIV_KEY_INFO pkcs8(d2i_PKCS8_PRIV_KEY_INFO(
            NULL, &pkcs_priv_key_p, key_blob.key_material_size));
    if (!pkcs8.get()) {
        LOG_E("Error parsing pkcs8 format private key.", 0);
        return ATAP_RESULT_ERROR_INVALID_INPUT;
    }
    Unique_EVP_PKEY pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (!pkey.get()) {
        LOG_E("Error parsing pkcs8 private key to EVP_PKEY.", 0);
        return ATAP_RESULT_ERROR_INVALID_INPUT;
    }

    Unique_EVP_MD_CTX mdctx(EVP_MD_CTX_create());

    if (!mdctx.get()) {
        LOG_E("Error creating md ctx.", 0);
        return ATAP_RESULT_ERROR_OOM;
    }
    EVP_PKEY_CTX* evp_pkey_ctx;
    if (1 != EVP_DigestSignInit(mdctx.get(), &evp_pkey_ctx, EVP_sha512(), NULL,
                                pkey.get())) {
        return ATAP_RESULT_ERROR_OOM;
    }
    if (key_type == ATAP_KEY_TYPE_RSA_SOM &&
        1 != EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, RSA_PKCS1_PADDING)) {
        return ATAP_RESULT_ERROR_CRYPTO;
    }

    if (1 != EVP_DigestSignUpdate(mdctx.get(), nonce, nonce_len)) {
        return ATAP_RESULT_ERROR_CRYPTO;
    }
    /* Get sig length. */
    size_t local_sig_len;
    if (1 != EVP_DigestSignFinal(mdctx.get(), NULL, &local_sig_len)) {
        return ATAP_RESULT_ERROR_CRYPTO;
    }
    if (local_sig_len > ATAP_SIGNATURE_LEN_MAX) {
        LOG_E("Signature length larger than the supported maximum signature length.",
              0);
        return ATAP_RESULT_ERROR_INVALID_INPUT;
    }
    /* Obtain the signature */
    if (1 != EVP_DigestSignFinal(mdctx.get(), sig, &local_sig_len)) {
        return ATAP_RESULT_ERROR_CRYPTO;
    }
    *sig_len = (uint32_t)local_sig_len;

    return ATAP_RESULT_OK;
}

}  // namespace keymaster
