#import "STRootListController.h"
#import <Foundation/Foundation.h>

#define PREFS_DOMAIN @"page.0x01.simtouch"
#define PREFS_CHANGED_NOTIFICATION "page.0x01.simtouch.prefsChanged"

@implementation STRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    [super setPreferenceValue:value specifier:specifier];
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(PREFS_CHANGED_NOTIFICATION), NULL, NULL, YES);
}

@end
