/*
 * Copyright 2015 The Android Open Source Project
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

#ifndef TRUSTY_APP_KEYMASTER_TRUSTY_KEYMASTER_CONTEXT_H_
#define TRUSTY_APP_KEYMASTER_TRUSTY_KEYMASTER_CONTEXT_H_

#include <stdlib.h>

#include <keymaster/UniquePtr.h>
#include <keymaster/attestation_context.h>
#include <keymaster/keymaster_context.h>
#include <keymaster/soft_key_factory.h>

#include <keymaster/km_openssl/software_random_source.h>

#include "trusty_keymaster_enforcement.h"

namespace keymaster {

class KeyFactory;

static const int kAuthTokenKeySize = 32;

class TrustyKeymasterContext : public KeymasterContext,
                               AttestationContext,
                               SoftwareKeyBlobMaker,
                               SoftwareRandomSource {
public:
    TrustyKeymasterContext();

    KmVersion GetKmVersion() const override {
        return AttestationContext::version_;
    }

    void SetKmVersion(KmVersion version) {
        AttestationContext::version_ = version;
    }

    keymaster_security_level_t GetSecurityLevel() const override {
        return KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
    }

    keymaster_error_t SetSystemVersion(uint32_t os_version,
                                       uint32_t os_patchlevel) override;
    void GetSystemVersion(uint32_t* os_version,
                          uint32_t* os_patchlevel) const override;

    const KeyFactory* GetKeyFactory(
            keymaster_algorithm_t algorithm) const override;
    OperationFactory* GetOperationFactory(
            keymaster_algorithm_t algorithm,
            keymaster_purpose_t purpose) const override;
    const keymaster_algorithm_t* GetSupportedAlgorithms(
            size_t* algorithms_count) const override;

    const VerifiedBootParams* GetVerifiedBootParams(
            keymaster_error_t* error) const override;

    keymaster_error_t CreateKeyBlob(
            const AuthorizationSet& key_description,
            keymaster_key_origin_t origin,
            const KeymasterKeyBlob& key_material,
            KeymasterKeyBlob* blob,
            AuthorizationSet* hw_enforced,
            AuthorizationSet* sw_enforced) const override;

    keymaster_error_t UpgradeKeyBlob(
            const KeymasterKeyBlob& key_to_upgrade,
            const AuthorizationSet& upgrade_params,
            KeymasterKeyBlob* upgraded_key) const override;

    keymaster_error_t ParseKeyBlob(const KeymasterKeyBlob& blob,
                                   const AuthorizationSet& additional_params,
                                   UniquePtr<Key>* key) const override {
        return ParseKeyBlob(blob, additional_params, key,
                            false /* allow_ocb */);
    }

    keymaster_error_t AddRngEntropy(const uint8_t* buf,
                                    size_t length) const override;

    keymaster_error_t GetAuthTokenKey(keymaster_key_blob_t* key) const;

    KeymasterEnforcement* enforcement_policy() override {
        return &enforcement_policy_;
    }

    keymaster_error_t VerifyAndCopyDeviceIds(
            const AuthorizationSet& attestation_params,
            AuthorizationSet* values_to_attest) const override;

    KeymasterKeyBlob GetAttestationKey(keymaster_algorithm_t algorithm,
                                       keymaster_error_t* error) const override;

    CertificateChain GetAttestationChain(
            keymaster_algorithm_t algorithm,
            keymaster_error_t* error) const override;

    CertificateChain GenerateAttestation(
            const Key& key,
            const AuthorizationSet& attest_params,
            UniquePtr<Key> attest_key,
            const KeymasterBlob& issuer_subject,
            keymaster_error_t* error) const override;

    CertificateChain GenerateSelfSignedCertificate(
            const Key& key,
            const AuthorizationSet& cert_params,
            bool fake_signature,
            keymaster_error_t* error) const override;

    keymaster_error_t SetBootParams(
            uint32_t /* os_version */,
            uint32_t /* os_patchlevel */,
            const Buffer& verified_boot_key,
            keymaster_verified_boot_t verified_boot_state,
            bool device_locked,
            const Buffer& verified_boot_hash);

    virtual keymaster_error_t UnwrapKey(
            const KeymasterKeyBlob& wrapped_key_blob,
            const KeymasterKeyBlob& wrapping_key_blob,
            const AuthorizationSet& wrapping_key_params,
            const KeymasterKeyBlob& masking_key,
            AuthorizationSet* wrapped_key_params,
            keymaster_key_format_t* wrapped_key_format,
            KeymasterKeyBlob* wrapped_key_material) const override;

    keymaster_error_t CheckConfirmationToken(
            const uint8_t* input_data,
            size_t input_data_size,
            const uint8_t confirmation_token[kConfirmationTokenSize])
            const override;

private:
    bool SeedRngIfNeeded() const;
    bool ShouldReseedRng() const;
    bool ReseedRng();
    bool InitializeAuthTokenKey();
    keymaster_error_t SetAuthorizations(const AuthorizationSet& key_description,
                                        keymaster_key_origin_t origin,
                                        AuthorizationSet* hw_enforced,
                                        AuthorizationSet* sw_enforced) const;
    keymaster_error_t BuildHiddenAuthorizations(
            const AuthorizationSet& input_set,
            AuthorizationSet* hidden) const;
    keymaster_error_t DeriveMasterKey(KeymasterKeyBlob* master_key) const;

    /*
     * This ParseKeyBlob overload does the actual work of parsing key blobs,
     * whether encrypted in AES-OCB mode or AES-GCM mode.  If allow_ocb is
     * false, blobs encrypted in AES-OCB mode will be rejected with
     * KM_ERROR_KEY_REQUIRES_UPGRADE, so the client will call UpgradeKey and get
     * the blob re-encrypted with AES-GCM.
     */
    keymaster_error_t ParseKeyBlob(const KeymasterKeyBlob& blob,
                                   const AuthorizationSet& additional_params,
                                   UniquePtr<Key>* key,
                                   bool allow_ocb) const;
    /*
     * CreateAuthEncryptedKeyBlob takes a key description authorization set, key
     * material, and hardware and software authorization sets and produces an
     * encrypted and integrity-checked key blob.
     *
     * This method is called by CreateKeyBlob and UpgradeKeyBlob.
     */
    keymaster_error_t CreateAuthEncryptedKeyBlob(
            const AuthorizationSet& key_description,
            const KeymasterKeyBlob& key_material,
            const AuthorizationSet& hw_enforced,
            const AuthorizationSet& sw_enforced,
            KeymasterKeyBlob* blob) const;

    TrustyKeymasterEnforcement enforcement_policy_;

    UniquePtr<KeyFactory> aes_factory_;
    UniquePtr<KeyFactory> ec_factory_;
    UniquePtr<KeyFactory> hmac_factory_;
    UniquePtr<KeyFactory> rsa_factory_;
    UniquePtr<KeyFactory> tdes_factory_;

    bool rng_initialized_;
    mutable int calls_since_reseed_;
    uint8_t auth_token_key_[kAuthTokenKeySize];
    bool auth_token_key_initialized_;

    bool root_of_trust_set_ = false;
    bool version_info_set_ = false;
    uint32_t boot_os_version_ = 0;
    uint32_t boot_os_patchlevel_ = 0;
    Buffer verified_boot_key_;
    keymaster_verified_boot_t verified_boot_state_ =
            KM_VERIFIED_BOOT_UNVERIFIED;
    bool device_locked_ = false;
    Buffer verified_boot_hash_;
    VerifiedBootParams verified_boot_params_ = {
            .verified_boot_key = {},
            .verified_boot_hash = {},
            .verified_boot_state = KM_VERIFIED_BOOT_UNVERIFIED,
            .device_locked = false};
};

}  // namespace keymaster

#endif  // TRUSTY_APP_KEYMASTER_TRUSTY_KEYMASTER_CONTEXT_H_
