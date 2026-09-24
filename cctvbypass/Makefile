INSTALL_TARGET_PROCESSES = CCTVVideo

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = CCTVBypass

CCTVBypass_FILES = Tweak.x
CCTVBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
CCTVBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
CCTVBypass_FRAMEWORKS = Foundation UIKit
CCTVBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
