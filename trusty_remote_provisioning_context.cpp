/*
 * Copyright 2021 The Android Open Source Project
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

#include "trusty_remote_provisioning_context.h"

#include <assert.h>
#include <algorithm>

#include <keymaster/cppcose/cppcose.h>
#include <keymaster/logger.h>
#include <lib/hwkey/hwkey.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include "keymaster_attributes.pb.h"
#include "secure_storage_manager.h"

namespace keymaster {

using cppcose::constructCoseSign1;
using cppcose::CoseKey;
using cppcose::ED25519;
using cppcose::EDDSA;
using cppcose::OCTET_KEY_PAIR;
using cppcose::VERIFY;

constexpr uint32_t kMacKeyLength = 32;

static const uint8_t kMasterKeyDerivationData[kMacKeyLength] =
        "RemoteKeyProvisioningMasterKey";

TrustyRemoteProvisioningContext::TrustyRemoteProvisioningContext() {
    std::tie(devicePrivKey_, bcc_) = GenerateBcc(false /* testMode */);
}

TrustyRemoteProvisioningContext::~TrustyRemoteProvisioningContext() {}

std::vector<uint8_t> TrustyRemoteProvisioningContext::DeriveBytesFromHbk(
        const std::string& context,
        size_t num_bytes) const {
    long rc = hwkey_open();
    if (rc < 0) {
        LOG_S("Couldn't open hwkey session: %d", rc);
        return {};
    }

    hwkey_session_t session = static_cast<hwkey_session_t>(rc);
    std::array<uint8_t, kMacKeyLength> hw_backed_key;

    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    rc = hwkey_derive(session, &kdf_version, kMasterKeyDerivationData,
                      hw_backed_key.data(), kMacKeyLength);

    if (rc < 0) {
        LOG_S("Error deriving master key: %d", rc);
        return {};
    }

    hwkey_close(session);

    std::vector<uint8_t> result(num_bytes);

    // TODO: Figure out if HKDF can fail.  It doesn't seem like it should be
    // able to, but the function does return an error code.
    HKDF(result.data(), num_bytes,                    //
         EVP_sha256(),                                //
         hw_backed_key.data(), hw_backed_key.size(),  //
         nullptr /* salt */, 0 /* salt len */,        //
         reinterpret_cast<const uint8_t*>(context.data()), context.size());

    return result;
}

#define ADD_ID_FIELD(array, proto, field_name)                              \
    if ((proto).size > 0) {                                                 \
        (array)->add(                                                       \
                (field_name),                                               \
                cppbor::Tstr((proto).bytes, (proto).bytes + (proto).size)); \
    }

std::unique_ptr<cppbor::Map> TrustyRemoteProvisioningContext::CreateDeviceInfo()
        const {
    auto result = std::make_unique<cppbor::Map>();

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();
    if (ss_manager == nullptr) {
        LOG_E("Failed to open secure storage session.", 0);
        return result;
    }

    AttestationIds ids;
    auto err = ss_manager->ReadAttestationIds(&ids);
    if (err != KM_ERROR_OK) {
        LOG_E("Failed to read attestation IDs", 0);
        return result;
    }
    ADD_ID_FIELD(result, ids.brand, "brand")
    ADD_ID_FIELD(result, ids.manufacturer, "manufacturer")
    ADD_ID_FIELD(result, ids.product, "product")
    ADD_ID_FIELD(result, ids.model, "model")
    ADD_ID_FIELD(result, ids.device, "device")
    if (bootParams_) {
        // KM validated device_locked and verified_boot_state combinations, so
        // there is no need to re-validate here.
        switch (bootParams_->verified_boot_state) {
        case KM_VERIFIED_BOOT_VERIFIED:
            result->add("vb_state", "green");
            break;
        case KM_VERIFIED_BOOT_SELF_SIGNED:
            result->add("vb_state", "yellow");
            break;
        case KM_VERIFIED_BOOT_UNVERIFIED:
            result->add("vb_state", "orange");
            break;
        default:
            break;
        }
        result->add("bootloader_state",
                    bootParams_->device_locked ? "locked" : "unlocked");
        result->add("os_version", std::to_string(bootParams_->boot_os_version));
        result->add("system_patch_level",
                    cppbor::Uint(bootParams_->boot_os_patchlevel));
    }

    result->canonicalize();
    return result;
}

std::pair<std::vector<uint8_t> /* privKey */, cppbor::Array /* BCC */>
TrustyRemoteProvisioningContext::GenerateBcc(bool testMode) const {
    std::vector<uint8_t> privKey(ED25519_PRIVATE_KEY_LEN);
    std::vector<uint8_t> pubKey(ED25519_PUBLIC_KEY_LEN);

    uint8_t seed[32];  // Length is hard-coded in the BoringCrypto API
    if (testMode) {
        RAND_bytes(seed, sizeof(seed));
    } else {
        auto seed_vector = DeriveBytesFromHbk("Device Key Seed", sizeof(seed));
        std::copy(seed_vector.begin(), seed_vector.end(), seed);
    }
    ED25519_keypair_from_seed(pubKey.data(), privKey.data(), seed);

    auto coseKey = cppbor::Map()
                           .add(CoseKey::KEY_TYPE, OCTET_KEY_PAIR)
                           .add(CoseKey::ALGORITHM, EDDSA)
                           .add(CoseKey::CURVE, ED25519)
                           .add(CoseKey::KEY_OPS, VERIFY)
                           .add(CoseKey::PUBKEY_X, pubKey)
                           .canonicalize();
    auto sign1Payload =
            cppbor::Map()
                    .add(1 /* Issuer */, "Issuer")
                    .add(2 /* Subject */, "Subject")
                    .add(-4670552 /* Subject Pub Key */, coseKey.encode())
                    .add(-4670553 /* Key Usage (little-endian order) */,
                         std::vector<uint8_t>{0x20} /* keyCertSign = 1<<5 */)
                    .canonicalize()
                    .encode();
    auto coseSign1 = constructCoseSign1(privKey,       /* signing key */
                                        cppbor::Map(), /* extra protected */
                                        sign1Payload, {} /* AAD */);
    assert(coseSign1);

    return {privKey,
            cppbor::Array().add(std::move(coseKey)).add(coseSign1.moveValue())};
}

std::optional<cppcose::HmacSha256>
TrustyRemoteProvisioningContext::GenerateHmacSha256(
        const cppcose::bytevec& input) const {
    auto key = DeriveBytesFromHbk("Key to MAC public keys", kMacKeyLength);
    auto result = cppcose::generateHmacSha256(key, input);
    if (!result) {
        LOG_E("Error signing MAC: %s", result.message().c_str());
        return std::nullopt;
    }
    return *result;
}

void TrustyRemoteProvisioningContext::SetBootParams(
        const BootParams* bootParams) {
    if (bootParamsSet_) {
        LOG_E("Boot parameters are already set in the remote provisioning context",
              0);
    }
    bootParamsSet_ = true;
    bootParams_ = bootParams;
}
}  // namespace keymaster
