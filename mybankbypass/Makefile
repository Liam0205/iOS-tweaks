INSTALL_TARGET_PROCESSES = Portal
THEOS_DEVICE_IP = 192.168.1.253
THEOS_DEVICE_PORT = 22

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MYBankBypass

MYBankBypass_FILES = Tweak.x
MYBankBypass_CFLAGS = -fobjc-arc
MYBankBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
