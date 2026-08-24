export THEOS ?= /home/liam/theos

INSTALL_TARGET_PROCESSES = China HongKong

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HSBCBypass

HSBCBypass_FILES = Tweak.x
HSBCBypass_CFLAGS = -fobjc-arc
HSBCBypass_LIBRARIES = substrate
ifeq ($(shell uname),Linux)
HSBCBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
HSBCBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
