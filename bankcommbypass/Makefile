INSTALL_TARGET_PROCESSES = 交通银行
THEOS_DEVICE_IP = 192.168.1.253
THEOS_DEVICE_PORT = 22

ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = BankcommBypass

BankcommBypass_FILES = Tweak.x
BankcommBypass_CFLAGS = -fobjc-arc
BankcommBypass_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
