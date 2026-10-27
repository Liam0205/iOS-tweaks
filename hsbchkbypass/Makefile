ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HSBCHKBypass

HSBCHKBypass_FILES = Tweak.x fishhook.c
HSBCHKBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
HSBCHKBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
HSBCHKBypass_FRAMEWORKS = Foundation UIKit
HSBCHKBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
