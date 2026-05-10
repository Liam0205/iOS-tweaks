INSTALL_TARGET_PROCESSES = ICBCBankTest
THEOS_DEVICE_IP = 192.168.31.191
THEOS_DEVICE_PORT = 22

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ICBCBypass

ICBCBypass_FILES = Tweak.x fishhook.c
ICBCBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
ICBCBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
ICBCBypass_FRAMEWORKS = Foundation UIKit QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
