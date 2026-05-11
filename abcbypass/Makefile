INSTALL_TARGET_PROCESSES = MbapMPaaS

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ABCBypass

ABCBypass_FILES = Tweak.x fishhook.c
ABCBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
ABCBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
ABCBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
