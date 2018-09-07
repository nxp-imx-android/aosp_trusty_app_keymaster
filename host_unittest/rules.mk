# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ATAP_DIR := $(TRUSTY_TOP)/system/iot/attestation/atap
KEYMASTER_ROOT := system/keymaster
KEYMASTER_DIR := trusty/user/app/keymaster
PB_GEN_DIR := $(call TOBUILDDIR,proto)

include trusty/user/base/make/compile_proto.mk
$(eval $(call compile_proto,$(KEYMASTER_DIR)/keymaster_attributes.proto,$(PB_GEN_DIR)))

HOST_TEST := keymaster_test

HOST_SRCS += \
	$(KEYMASTER_DIR)/secure_storage_manager.cpp \
	$(KEYMASTER_DIR)/host_unittest/main.cpp \
	$(KEYMASTER_ROOT)/android_keymaster/logger.cpp \
	$(NANOPB_DEPS) \
	$(NANOPB_GENERATED_C) \
	$(ATAP_DIR)/libatap/atap_util.c \
	$(ATAP_DIR)/libatap/atap_sysdeps_posix.c \

HOST_INCLUDE_DIRS := \
	$(KEYMASTER_ROOT) \
	$(KEYMASTER_DIR)/host_unittest \
	$(KEYMASTER_DIR) \
	$(KEYMASTER_ROOT)/include \
	hardware/libhardware/include \
	lib/lib/storage/include \
	lib/interface/storage/include \
	$(NANOPB_DIR) \
	$(PB_GEN_DIR) \
	$(ATAP_DIR) \

HOST_FLAGS := -Wpointer-arith \
	-Wno-deprecated-declarations -fno-exceptions \
	-DSTORAGE_FAKE \
	-DPB_FIELD_16BIT \
	-DPB_NO_STATIC_ASSERT \

HOST_LIBS := \
	stdc++ \

# These rules are used to force .pb.h file to be generated before compiling
# these files.
$(KEYMASTER_DIR)/secure_storage_manager.cpp: $(NANOPB_GENERATED_HEADER)
$(KEYMASTER_DIR)/host_unittest/main.cpp: $(NANOPB_GENERATED_HEADER)

include trusty/user/app/storage/storage_mock/add_mock_storage.mk
include make/host_test.mk
