ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WHBypass

WHBypass_FILES = Tweak.x
WHBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
WHBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
WHBypass_FRAMEWORKS = Foundation UIKit
WHBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
