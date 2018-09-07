/*
 * Copyright (C) 2018 The Android Open Source Project
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

/**
 * This app tests the API in app/keymaster/secure_storage.h. To run this test,
 * include keymaster/storage_test in TRUSTY_ALL_USER_TASKS, and it will be start
 * once an RPMB proxy becomes available.
 *
 * Different application has different namespace, so this would not affect the
 * keymaster app's RPMB storage.
 */

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#ifndef __clang__
// We need to diable foritfy level for memset in gcc because we want to use
// memset unoptimized. This would falsely trigger __warn_memset_zero_len in
// /usr/include/bits/string3.h. The inline checking function is only supposed to
// work when the optimization level is at least 1. In android_keymaster_utils.h
// we would use memset unoptimized.
#pragma push_macro("__USE_FORTIFY_LEVEL")
#undef __USE_FORTIFY_LEVEL
#endif
#include <string.h>
#ifndef __clang__
#pragma pop_macro("__USE_FORTIFY_LEVEL")
#endif
#include <fstream>

#define typeof(x) __typeof__(x)
#include <trusty_unittest.h>

extern "C" {
#include <libatap/atap_util.h>
}

#include <keymaster/android_keymaster_utils.h>
#include "secure_storage_manager.h"

#define DATA_SIZE 2048
#define CHAIN_LENGTH 3

#define EXPECT_ALL_OK()  \
    if (!_all_ok) {      \
        goto test_abort; \
    }

#define LOG_TAG "km_storage_test"

#define ASSERT_EQ(e, a)      \
    do {                     \
        EXPECT_EQ(e, a, ""); \
        EXPECT_ALL_OK();     \
    } while (0)

#define ASSERT_NE(e, a)      \
    do {                     \
        EXPECT_NE(e, a, ""); \
        EXPECT_ALL_OK();     \
    } while (0)

using keymaster::AttestationKeySlot;
using keymaster::CertificateChainDelete;
using keymaster::kAttestationUuidSize;
using keymaster::KeymasterKeyBlob;
using keymaster::kProductIdSize;
using keymaster::SecureStorageManager;

uint8_t* NewRandBuf(size_t size) {
    uint8_t* buf = new uint8_t[size];
    for (uint8_t* i = buf;
         reinterpret_cast<size_t>(i) < reinterpret_cast<size_t>(buf) + size;
         i++) {
        *i = static_cast<uint8_t>(rand() % UINT8_MAX);
    }
    return buf;
}

void TestKeyStorage(SecureStorageManager* ss_manager,
                    AttestationKeySlot key_slot) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_key;
    KeymasterKeyBlob key_blob;
    bool key_exists = false;

    TEST_BEGIN(__func__);

    write_key.reset(NewRandBuf(DATA_SIZE));
    ASSERT_NE(nullptr, write_key.get());

    error = ss_manager->WriteKeyToStorage(key_slot, write_key.get(), DATA_SIZE);
    ASSERT_EQ(KM_ERROR_OK, error);

    key_blob = ss_manager->ReadKeyFromStorage(key_slot, &error);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(DATA_SIZE, key_blob.key_material_size);
    ASSERT_NE(nullptr, write_key.get());
    ASSERT_EQ(0, memcmp(write_key.get(), key_blob.writable_data(), DATA_SIZE));

    error = ss_manager->AttestationKeyExists(key_slot, &key_exists);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(true, key_exists);

test_abort:
    TEST_END;
}

void TestCertChainStorage(SecureStorageManager* ss_manager,
                          AttestationKeySlot key_slot,
                          bool chain_exists) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_cert[CHAIN_LENGTH];
    unsigned int i = 0;
    uint32_t cert_chain_length;
    keymaster::UniquePtr<keymaster_cert_chain_t, CertificateChainDelete> chain;

    TEST_BEGIN(__func__);

    for (i = 0; i < CHAIN_LENGTH; ++i) {
        write_cert[i].reset(NewRandBuf(DATA_SIZE));
        ASSERT_NE(nullptr, write_cert[i].get());

        error = ss_manager->WriteCertToStorage(key_slot, write_cert[i].get(),
                                               DATA_SIZE, i);
        ASSERT_EQ(KM_ERROR_OK, error);

        error = ss_manager->ReadCertChainLength(key_slot, &cert_chain_length);
        ASSERT_EQ(KM_ERROR_OK, error);
        if (chain_exists) {
            ASSERT_EQ(3, cert_chain_length);
        } else {
            ASSERT_EQ(i + 1, cert_chain_length);
        }
    }

    chain.reset(new keymaster_cert_chain_t);
    ASSERT_NE(nullptr, chain.get());
    error = ss_manager->ReadCertChainFromStorage(key_slot, chain.get());
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(CHAIN_LENGTH, chain.get()->entry_count);
    for (i = 0; i < CHAIN_LENGTH; ++i) {
        ASSERT_EQ(DATA_SIZE, chain.get()->entries[i].data_length);
        ASSERT_EQ(0, memcmp(write_cert[i].get(), chain.get()->entries[i].data,
                            DATA_SIZE));
    }

    error = ss_manager->DeleteCertChainFromStorage(key_slot);
    ASSERT_EQ(KM_ERROR_OK, error);
    chain.reset(new keymaster_cert_chain_t);
    error = ss_manager->ReadCertChainFromStorage(key_slot, chain.get());
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(0, chain.get()->entry_count);

test_abort:
    TEST_END;
}

void TestAtapCertChainStorage(SecureStorageManager* ss_manager,
                              AttestationKeySlot key_slot,
                              bool chain_exists) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_cert[CHAIN_LENGTH];
    keymaster::UniquePtr<uint8_t[]> write_key;
    KeymasterKeyBlob key_blob;
    bool key_exists = false;
    uint32_t cert_chain_length;
    AtapCertChain read_chain;
    AtapCertChain write_chain;
    memset(&read_chain, 0, sizeof(AtapCertChain));
    memset(&write_chain, 0, sizeof(AtapCertChain));

    TEST_BEGIN(__func__);
    write_chain.entry_count = CHAIN_LENGTH;

    for (size_t i = 0; i < CHAIN_LENGTH; ++i) {
        write_cert[i].reset(NewRandBuf(DATA_SIZE));
        ASSERT_NE(nullptr, write_cert[i].get());
        write_chain.entries[i].data_length = DATA_SIZE;
        write_chain.entries[i].data =
                reinterpret_cast<uint8_t*>(atap_malloc(DATA_SIZE));
        ASSERT_NE(nullptr, write_chain.entries[i].data);
        memcpy(write_chain.entries[i].data, write_cert[i].get(), DATA_SIZE);
    }
    write_key.reset(NewRandBuf(DATA_SIZE));
    ASSERT_NE(nullptr, write_key.get());
    error = ss_manager->WriteAtapKeyAndCertsToStorage(key_slot, write_key.get(),
                                                      DATA_SIZE, &write_chain);
    ASSERT_EQ(KM_ERROR_OK, error);

    error = ss_manager->ReadCertChainLength(key_slot, &cert_chain_length);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(3, cert_chain_length);

    memset(&read_chain, 0, sizeof(AtapCertChain));
    error = ss_manager->ReadAtapCertChainFromStorage(key_slot, &read_chain);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(CHAIN_LENGTH, read_chain.entry_count);
    for (size_t i = 0; i < CHAIN_LENGTH; ++i) {
        ASSERT_EQ(DATA_SIZE, read_chain.entries[i].data_length);
        ASSERT_EQ(0, memcmp(write_cert[i].get(), read_chain.entries[i].data,
                            DATA_SIZE));
    }
    key_blob = ss_manager->ReadKeyFromStorage(key_slot, &error);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(DATA_SIZE, key_blob.key_material_size);
    ASSERT_NE(nullptr, write_key.get());
    ASSERT_EQ(0, memcmp(write_key.get(), key_blob.writable_data(), DATA_SIZE));

    error = ss_manager->AttestationKeyExists(key_slot, &key_exists);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(true, key_exists);

test_abort:
    free_cert_chain(read_chain);
    free_cert_chain(write_chain);
    TEST_END;
}

void TestCertStorageInvalid(SecureStorageManager* ss_manager,
                            AttestationKeySlot key_slot) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_cert;
    uint32_t cert_chain_length;

    TEST_BEGIN(__func__);

    // Clear existing certificate chain
    error = ss_manager->DeleteKey(key_slot, true);
    ASSERT_EQ(KM_ERROR_OK, error);
    error = ss_manager->ReadCertChainLength(key_slot, &cert_chain_length);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(0, cert_chain_length);

    // Try to write to index (chain_length + 1)
    write_cert.reset(NewRandBuf(DATA_SIZE));
    ASSERT_NE(nullptr, write_cert.get());
    error = ss_manager->WriteCertToStorage(key_slot, write_cert.get(),
                                           DATA_SIZE, 1);
    ASSERT_EQ(KM_ERROR_INVALID_ARGUMENT, error);

    // Verify that cert chain length didn't change
    error = ss_manager->ReadCertChainLength(key_slot, &cert_chain_length);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(0, cert_chain_length);

test_abort:
    TEST_END;
}

void DeleteAttestationData(SecureStorageManager* ss_manager) {
    keymaster_error_t error = KM_ERROR_OK;
    uint32_t cert_chain_length;
    bool key_exists;

    TEST_BEGIN(__func__);

    error = ss_manager->DeleteAllAttestationData();
    ASSERT_EQ(KM_ERROR_OK, error);

    error = ss_manager->ReadCertChainLength(AttestationKeySlot::kRsa,
                                            &cert_chain_length);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(0, cert_chain_length);
    error = ss_manager->ReadCertChainLength(AttestationKeySlot::kEcdsa,
                                            &cert_chain_length);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(0, cert_chain_length);

    error = ss_manager->AttestationKeyExists(AttestationKeySlot::kRsa,
                                             &key_exists);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(false, key_exists);
    error = ss_manager->AttestationKeyExists(AttestationKeySlot::kEcdsa,
                                             &key_exists);
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_EQ(false, key_exists);

test_abort:
    TEST_END;
}

void TestUuidStorage(SecureStorageManager* ss_manager) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_uuid;
    keymaster::UniquePtr<uint8_t[]> read_uuid(
            new uint8_t[kAttestationUuidSize]);

    TEST_BEGIN(__func__);

    error = ss_manager->DeleteAttestationUuid();
    ASSERT_EQ(KM_ERROR_OK, error);

    write_uuid.reset(NewRandBuf(kAttestationUuidSize));
    ASSERT_NE(nullptr, write_uuid.get());

    error = ss_manager->WriteAttestationUuid((const uint8_t*)write_uuid.get());
    ASSERT_EQ(KM_ERROR_OK, error);

    error = ss_manager->ReadAttestationUuid(read_uuid.get());
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_NE(nullptr, read_uuid.get());
    ASSERT_EQ(0, memcmp(write_uuid.get(), read_uuid.get(), kProductIdSize));

    error = ss_manager->DeleteAttestationUuid();
    ASSERT_EQ(KM_ERROR_OK, error);

test_abort:
    TEST_END;
}

void TestProductIdStorage(SecureStorageManager* ss_manager) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_productid;
    keymaster::UniquePtr<uint8_t[]> read_productid(new uint8_t[kProductIdSize]);

    TEST_BEGIN(__func__);

    error = ss_manager->DeleteProductId();
    ASSERT_EQ(KM_ERROR_OK, error);

    write_productid.reset(NewRandBuf(kProductIdSize));
    ASSERT_NE(nullptr, write_productid.get());

    error = ss_manager->SetProductId((const uint8_t*)write_productid.get());
    ASSERT_EQ(KM_ERROR_OK, error);

    error = ss_manager->ReadProductId(read_productid.get());
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_NE(nullptr, read_productid.get());
    ASSERT_EQ(0, memcmp(write_productid.get(), read_productid.get(),
                        kProductIdSize));

    error = ss_manager->DeleteProductId();
    ASSERT_EQ(KM_ERROR_OK, error);

test_abort:
    TEST_END;
}

void TestProductIdStoragePreventOverwrite(SecureStorageManager* ss_manager) {
    keymaster_error_t error = KM_ERROR_OK;
    keymaster::UniquePtr<uint8_t[]> write_productid;
    keymaster::UniquePtr<uint8_t[]> overwrite_productid;
    keymaster::UniquePtr<uint8_t[]> read_productid(new uint8_t[kProductIdSize]);

    TEST_BEGIN(__func__);

    error = ss_manager->DeleteProductId();
    ASSERT_EQ(KM_ERROR_OK, error);

    write_productid.reset(NewRandBuf(kProductIdSize));
    ASSERT_NE(nullptr, write_productid.get());

    error = ss_manager->SetProductId((const uint8_t*)write_productid.get());
    ASSERT_EQ(KM_ERROR_OK, error);

    overwrite_productid.reset(NewRandBuf(kProductIdSize));
    error = ss_manager->SetProductId((const uint8_t*)write_productid.get());
    ASSERT_EQ(KM_ERROR_INVALID_ARGUMENT, error);

    error = ss_manager->ReadProductId(read_productid.get());
    ASSERT_EQ(KM_ERROR_OK, error);
    ASSERT_NE(nullptr, read_productid.get());
    ASSERT_EQ(0, memcmp(write_productid.get(), read_productid.get(),
                        kProductIdSize));

    error = ss_manager->DeleteProductId();
    ASSERT_EQ(KM_ERROR_OK, error);

test_abort:
    TEST_END;
}

int main(void) {
    TLOGI("Welcome to keymaster unit test -------------------------\n\n");

    SecureStorageManager* ss_manager = SecureStorageManager::get_instance();

    DeleteAttestationData(ss_manager);

    TestKeyStorage(ss_manager, AttestationKeySlot::kRsa);
    TestKeyStorage(ss_manager, AttestationKeySlot::kEcdsa);
    TestCertChainStorage(ss_manager, AttestationKeySlot::kRsa, false);
    TestCertChainStorage(ss_manager, AttestationKeySlot::kEcdsa, false);
    TestAtapCertChainStorage(ss_manager, AttestationKeySlot::kRsa, false);
    TestAtapCertChainStorage(ss_manager, AttestationKeySlot::kEcdsa, false);

    // Rewriting keys should work
    TestKeyStorage(ss_manager, AttestationKeySlot::kRsa);
    TestCertChainStorage(ss_manager, AttestationKeySlot::kRsa, true);

    TestCertStorageInvalid(ss_manager, AttestationKeySlot::kRsa);

    TestUuidStorage(ss_manager);
    TestProductIdStorage(ss_manager);

#ifndef KEYMASTER_DEBUG
    TestProductIdStoragePreventOverwrite(ss_manager);
#endif

    DeleteAttestationData(ss_manager);

    TLOGI("Keymaster unit tests done ------------------------------\n\n");
    TLOGI("PASSED: %u, FAILED: %u\n", _tests_total - _tests_failed,
          _tests_failed);
    if (_tests_failed > 0) {
        return -1;
    }
    return 0;
}
