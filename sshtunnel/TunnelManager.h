#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, TunnelState) {
    TunnelStateDisconnected,
    TunnelStateConnecting,
    TunnelStateConnected,
};

typedef void (^TunnelStateCallback)(TunnelState state, NSString * _Nullable message);

NS_ASSUME_NONNULL_BEGIN

@interface TunnelManager : NSObject

@property (nonatomic, readonly) TunnelState state;
@property (nonatomic, copy, nullable) TunnelStateCallback onStateChange;

@property (nonatomic, copy, nullable) NSString *serverHost;
@property (nonatomic, assign) NSInteger serverPort;
@property (nonatomic, copy, nullable) NSString *username;
@property (nonatomic, assign) NSInteger remotePort;
@property (nonatomic, assign) NSInteger localPort;
@property (nonatomic, copy) NSString *identityFile;

@property (nonatomic, copy, nullable) NSString *lastMessage;
@property (nonatomic, readonly) BOOL usingAutossh;

+ (instancetype)shared;
- (void)probe;
- (void)connect;
- (void)disconnect;
- (void)saveSettings;
- (void)loadSettings;

@end

NS_ASSUME_NONNULL_END
