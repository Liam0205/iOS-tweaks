INSTALL_TARGET_PROCESSES = China

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HSBCChinaBypass

HSBCChinaBypass_FILES = Tweak.x
HSBCChinaBypass_CFLAGS = -fobjc-arc
HSBCChinaBypass_LIBRARIES = substrate
ifeq ($(shell uname),Linux)
HSBCChinaBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
HSBCChinaBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
