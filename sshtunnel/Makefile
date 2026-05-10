IPHONE_ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME = rootless

ifeq ($(shell uname),Linux)
export LD_LIBRARY_PATH := /home/linuxbrew/.linuxbrew/lib:$(LD_LIBRARY_PATH)
endif

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = SSHTunnel

SSHTunnel_FILES = main.m SSHTunnelApp.m TunnelViewController.m TunnelManager.m KeyManager.m
SSHTunnel_FRAMEWORKS = UIKit Foundation Security
SSHTunnel_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
SSHTunnel_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif
SSHTunnel_CODESIGN_FLAGS = -Sentitlements.plist
SSHTunnel_INSTALL_PATH = /Applications

include $(THEOS_MAKE_PATH)/application.mk
