//
//  AesCrypt.h
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AesCrypt : NSObject
+ (NSString *) initCipher: (NSString *)mode  key: (NSString *)key iv: (NSString *)iv;
+ (NSData *) encrypt: (NSString *)uniqueID data: (NSData *)data;
+ (NSString *) update: (NSString *)uniqueID data: (NSString *)data;
+ (NSString *) doFinal: (NSString *)uniqueID data: (NSString *)data;
+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length;
+ (NSString *) hmac256: (NSString *)input key: (NSString *)key;
+ (NSString *) sha1: (NSString *)input;
+ (NSString *) sha256: (NSString *)input;
+ (NSString *) sha512: (NSString *)input;
+ (NSString *) toHex: (NSData *)nsdata;
+ (NSString *) randomUuid;
+ (NSString *) randomKey: (NSInteger)length;
@end
