INSTALL_TARGET_PROCESSES = LianJiaShell LJShell

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LianJiaBypass

LianJiaBypass_FILES = Tweak.x fishhook.c
LianJiaBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
LianJiaBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
LianJiaBypass_FRAMEWORKS = Foundation UIKit
LianJiaBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
