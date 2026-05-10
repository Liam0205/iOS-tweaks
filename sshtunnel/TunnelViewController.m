#import "TunnelViewController.h"
#import "TunnelManager.h"
#import "KeyManager.h"

typedef NS_ENUM(NSInteger, Section) {
    SectionServer,
    SectionTunnel,
    SectionKey,
    SectionAction,
    SectionCount
};

@implementation TunnelViewController {
    UITextField *_hostField;
    UITextField *_portField;
    UITextField *_userField;
    UITextField *_remotePortField;
    UITextField *_localPortField;
    UITextField *_identityField;
    UILabel *_statusLabel;
    UILabel *_pubKeyLabel;
    UIButton *_connectButton;
}

- (instancetype)init {
    return [super initWithStyle:UITableViewStyleGrouped];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"SSH Tunnel";
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeInteractive;

    TunnelManager *mgr = [TunnelManager shared];
    __weak typeof(self) weakSelf = self;
    mgr.onStateChange = ^(TunnelState state, NSString *msg) {
        [weakSelf updateUIForState:state message:msg];
    };

    [self updateUIForState:mgr.state message:nil];
}

#pragma mark - UITableView

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv {
    return SectionCount;
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case SectionServer:  return 3;
        case SectionTunnel:  return 3;
        case SectionKey:     return 2;
        case SectionAction:  return 1;
        default: return 0;
    }
}

- (NSString *)tableView:(UITableView *)tv titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case SectionServer:  return @"Server";
        case SectionTunnel:  return @"Tunnel";
        case SectionKey:     return @"SSH Key";
        case SectionAction:  return nil;
        default: return nil;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    TunnelManager *mgr = [TunnelManager shared];

    if (ip.section == SectionAction) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        _statusLabel = [[UILabel alloc] init];
        _statusLabel.font = [UIFont systemFontOfSize:12];
        _statusLabel.textColor = UIColor.secondaryLabelColor;
        _statusLabel.numberOfLines = 0;
        _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

        _connectButton = [UIButton buttonWithType:UIButtonTypeSystem];
        _connectButton.titleLabel.font = [UIFont boldSystemFontOfSize:17];
        [_connectButton addTarget:self action:@selector(toggleConnection) forControlEvents:UIControlEventTouchUpInside];
        _connectButton.translatesAutoresizingMaskIntoConstraints = NO;

        UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[_connectButton, _statusLabel]];
        stack.axis = UILayoutConstraintAxisVertical;
        stack.spacing = 6;
        stack.alignment = UIStackViewAlignmentCenter;
        stack.translatesAutoresizingMaskIntoConstraints = NO;
        [cell.contentView addSubview:stack];
        [NSLayoutConstraint activateConstraints:@[
            [stack.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:12],
            [stack.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-12],
            [stack.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:16],
            [stack.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-16],
        ]];

        [self updateUIForState:mgr.state message:nil];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }

    if (ip.section == SectionKey) {
        if (ip.row == 0) {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            cell.textLabel.text = @"Generate New Key";
            cell.textLabel.textColor = self.view.tintColor;
            cell.textLabel.textAlignment = NSTextAlignmentCenter;
            return cell;
        } else {
            UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
            _pubKeyLabel = [[UILabel alloc] init];
            _pubKeyLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
            _pubKeyLabel.numberOfLines = 0;
            _pubKeyLabel.lineBreakMode = NSLineBreakByCharWrapping;
            _pubKeyLabel.translatesAutoresizingMaskIntoConstraints = NO;
            [cell.contentView addSubview:_pubKeyLabel];
            [NSLayoutConstraint activateConstraints:@[
                [_pubKeyLabel.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:10],
                [_pubKeyLabel.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-10],
                [_pubKeyLabel.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:16],
                [_pubKeyLabel.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-16],
            ]];
            [self refreshPublicKey];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            return cell;
        }
    }

    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    UITextField *tf = [[UITextField alloc] init];
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    tf.returnKeyType = UIReturnKeyDone;
    tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tf.autocorrectionType = UITextAutocorrectionTypeNo;
    tf.translatesAutoresizingMaskIntoConstraints = NO;
    [tf addTarget:self action:@selector(fieldChanged:) forControlEvents:UIControlEventEditingChanged];
    [cell.contentView addSubview:tf];

    UILabel *label = [[UILabel alloc] init];
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = UIColor.secondaryLabelColor;
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [label setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    [cell.contentView addSubview:label];

    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:16],
        [label.centerYAnchor constraintEqualToAnchor:cell.contentView.centerYAnchor],
        [label.widthAnchor constraintEqualToConstant:100],
        [tf.leadingAnchor constraintEqualToAnchor:label.trailingAnchor constant:8],
        [tf.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-16],
        [tf.centerYAnchor constraintEqualToAnchor:cell.contentView.centerYAnchor],
    ]];

    if (ip.section == SectionServer) {
        switch (ip.row) {
            case 0:
                label.text = @"Host";
                tf.placeholder = @"example.com";
                tf.text = mgr.serverHost;
                tf.keyboardType = UIKeyboardTypeURL;
                _hostField = tf;
                break;
            case 1:
                label.text = @"Port";
                tf.placeholder = @"22";
                tf.text = [NSString stringWithFormat:@"%ld", (long)mgr.serverPort];
                tf.keyboardType = UIKeyboardTypeNumberPad;
                _portField = tf;
                break;
            case 2:
                label.text = @"Username";
                tf.placeholder = @"root";
                tf.text = mgr.username;
                _userField = tf;
                break;
        }
    } else {
        switch (ip.row) {
            case 0:
                label.text = @"Remote Port";
                tf.placeholder = @"2222";
                tf.text = [NSString stringWithFormat:@"%ld", (long)mgr.remotePort];
                tf.keyboardType = UIKeyboardTypeNumberPad;
                _remotePortField = tf;
                break;
            case 1:
                label.text = @"Local Port";
                tf.placeholder = @"22";
                tf.text = [NSString stringWithFormat:@"%ld", (long)mgr.localPort];
                tf.keyboardType = UIKeyboardTypeNumberPad;
                _localPortField = tf;
                break;
            case 2:
                label.text = @"Identity";
                tf.placeholder = @"~/.ssh/id_rsa";
                tf.text = mgr.identityFile;
                tf.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
                _identityField = tf;
                break;
        }
    }

    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    if (ip.section == SectionKey && ip.row == 0) {
        [self generateKey];
    }
}

#pragma mark - Actions

- (void)fieldChanged:(UITextField *)tf {
    TunnelManager *mgr = [TunnelManager shared];
    if (tf == _hostField)       mgr.serverHost = tf.text;
    else if (tf == _portField)  mgr.serverPort = tf.text.integerValue;
    else if (tf == _userField)  mgr.username = tf.text;
    else if (tf == _remotePortField) mgr.remotePort = tf.text.integerValue;
    else if (tf == _localPortField)  mgr.localPort = tf.text.integerValue;
    else if (tf == _identityField)   mgr.identityFile = tf.text;
}

- (void)toggleConnection {
    TunnelManager *mgr = [TunnelManager shared];
    if (mgr.state == TunnelStateDisconnected) {
        [self.view endEditing:YES];
        [mgr connect];
    } else {
        [mgr disconnect];
    }
}

- (void)generateKey {
    TunnelManager *mgr = [TunnelManager shared];
    NSString *path = mgr.identityFile;

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Generate SSH Key"
        message:[NSString stringWithFormat:@"Generate a new ed25519 key at %@?\nExisting key will be overwritten.", path]
        preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Generate" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [KeyManager generateKeyAtPath:path completion:^(BOOL ok, NSString *err) {
            if (ok) {
                [self refreshPublicKey];
            } else {
                UIAlertController *errAlert = [UIAlertController
                    alertControllerWithTitle:@"Error" message:err preferredStyle:UIAlertControllerStyleAlert];
                [errAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:errAlert animated:YES completion:nil];
            }
        }];
    }]];

    [self presentViewController:alert animated:YES completion:nil];
}

- (void)refreshPublicKey {
    TunnelManager *mgr = [TunnelManager shared];
    NSString *path = mgr.identityFile;
    NSString *pub = [KeyManager publicKeyForPath:path];
    _pubKeyLabel.text = pub.length ? pub : @"No public key found. Tap \"Generate New Key\" above.";
    _pubKeyLabel.textColor = pub.length ? UIColor.labelColor : UIColor.tertiaryLabelColor;
}

- (void)updateUIForState:(TunnelState)state message:(NSString *)msg {
    BOOL connected = (state != TunnelStateDisconnected);
    NSString *title;
    UIColor *color;

    switch (state) {
        case TunnelStateDisconnected:
            title = @"Connect";
            color = self.view.tintColor;
            break;
        case TunnelStateConnecting:
            title = @"Connecting...";
            color = UIColor.systemOrangeColor;
            break;
        case TunnelStateConnected:
            title = @"Disconnect";
            color = UIColor.systemRedColor;
            break;
    }

    [_connectButton setTitle:title forState:UIControlStateNormal];
    [_connectButton setTitleColor:color forState:UIControlStateNormal];
    _connectButton.enabled = (state != TunnelStateConnecting);
    _statusLabel.text = msg ?: @"";

    _hostField.enabled = !connected;
    _portField.enabled = !connected;
    _userField.enabled = !connected;
    _remotePortField.enabled = !connected;
    _localPortField.enabled = !connected;
    _identityField.enabled = !connected;
}

@end
