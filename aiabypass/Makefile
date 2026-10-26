ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AIABypass

AIABypass_FILES = Tweak.x
AIABypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
AIABypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
AIABypass_FRAMEWORKS = Foundation UIKit
AIABypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
