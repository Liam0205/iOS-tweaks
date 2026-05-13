INSTALL_TARGET_PROCESSES = SpringBoard backboardd

ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SimTouch
SimTouch_FILES = Tweak.x BackboardHook.x SocketServer.m ScreenCapture.m TouchInjector.m
SimTouch_CFLAGS = -fobjc-arc -Wno-arc-performSelector-leaks
SimTouch_FRAMEWORKS = Foundation UIKit IOKit
SimTouch_PRIVATE_FRAMEWORKS = FrontBoardServices MobileCoreServices
SimTouch_LIBRARIES = substrate
ifeq ($(shell uname),Linux)
SimTouch_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif

include $(THEOS_MAKE_PATH)/tweak.mk

TOOL_NAME = simtouch
simtouch_FILES = tools/simtouch.c
simtouch_FRAMEWORKS = CoreFoundation
simtouch_INSTALL_PATH = /usr/bin
ifeq ($(shell uname),Linux)
simtouch_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif

include $(THEOS_MAKE_PATH)/tool.mk

BUNDLE_NAME = SimTouchPrefs
SimTouchPrefs_FILES = simtouchprefs/STRootListController.m
SimTouchPrefs_FRAMEWORKS = UIKit
SimTouchPrefs_PRIVATE_FRAMEWORKS = Preferences
SimTouchPrefs_INSTALL_PATH = /Library/PreferenceBundles
SimTouchPrefs_RESOURCE_DIRS = simtouchprefs/Resources
SimTouchPrefs_CFLAGS = -fobjc-arc
ifeq ($(shell uname),Linux)
SimTouchPrefs_LDFLAGS = -B$(THEOS)/toolchain/linux/iphone/bin -fuse-ld=$(THEOS)/toolchain/linux/iphone/bin/ld
endif

include $(THEOS_MAKE_PATH)/bundle.mk
