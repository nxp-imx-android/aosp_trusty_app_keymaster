# Copyright (C) 2017 The Android Open Source Project
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

LOCAL_DIR := $(GET_LOCAL_DIR)
KEYMASTER_ROOT := system/keymaster
KEYMASTER_DIR := trusty/user/app/keymaster
PB_GEN_DIR := $(call TOBUILDDIR,proto)
MODULE := $(LOCAL_DIR)

include trusty/user/base/make/compile_proto.mk
$(eval $(call compile_proto,$(KEYMASTER_DIR)/keymaster_attributes.proto,$(PB_GEN_DIR)))

MODULE_SRCS += \
	$(KEYMASTER_DIR)/secure_storage_manager.cpp \
	$(LOCAL_DIR)/main.cpp \
	$(LOCAL_DIR)/manifest.c \
	$(KEYMASTER_ROOT)/android_keymaster/logger.cpp \
	$(NANOPB_DEPS) \
	$(NANOPB_GENERATED_C) \

MODULE_DEPS += \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/lib/libstdc++-trusty \
	trusty/user/base/lib/rng \
	trusty/user/base/lib/storage \
	trusty/user/base/lib/unittest \

MODULE_SRCDEPS += \
	$(NANOPB_GENERATED_HEADER) \

MODULE_COMPILEFLAGS += -DPB_FIELD_16BIT
MODULE_COMPILEFLAGS += -DPB_NO_STATIC_ASSERT

MODULE_INCLUDES := \
	$(KEYMASTER_ROOT) \
	$(LOCAL_DIR) \
	$(KEYMASTER_DIR) \
	$(KEYMASTER_ROOT)/include \
	hardware/libhardware/include \
	lib/lib/storage/include \
	lib/interface/storage/include \
	$(NANOPB_DIR) \
	$(PB_GEN_DIR) \
	$(TRUSTY_TOP)/system/iot/attestation/atap \

include make/module.mk

