INSTALL_TARGET_PROCESSES = SpringBoard

ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SimTouch
SimTouch_FILES = Tweak.x SocketServer.m
SimTouch_CFLAGS = -fobjc-arc
SimTouch_FRAMEWORKS = Foundation UIKit
SimTouch_LIBRARIES = substrate
ifeq ($(shell uname),Linux)
SimTouch_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
