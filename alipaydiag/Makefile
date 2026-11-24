ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AlipayDiag

AlipayDiag_FILES = Tweak.x
AlipayDiag_CFLAGS = -fobjc-arc
AlipayDiag_FRAMEWORKS = Foundation UIKit
ifeq ($(shell uname),Linux)
AlipayDiag_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
