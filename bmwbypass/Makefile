INSTALL_TARGET_PROCESSES = My BMW

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = BMWBypass

BMWBypass_FILES = Tweak.x
BMWBypass_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
BMWBypass_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
BMWBypass_FRAMEWORKS = Foundation
BMWBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
