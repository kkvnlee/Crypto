//
//  KLAESCryptor.h
//  ComCryptor
//
//  Created by kevin on 2020/7/8.
//  Copyright © 2020 kevin. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*
 PKCS7 + CBC 的AES加密解密 ，适配java同模式
 
 1、支持数据data、字符串进行加密
 2、支持文件进行加密，对大文件进行分段进行。同步/异步两种
 3、提供EAES的加密key生成
 
 */

typedef void (^KLCRyptorFileBlock)(NSError *error);

@interface KLAESCryptor : NSObject

//生成AESKEY【legth 偶数】
+ (NSString *)generateAesKeyWithLength:(NSInteger)length;

//对string进行加密
+ (NSString *)encryptString:(NSString *)srcString password:(NSString *)password error:(NSError **)error;
+ (NSString *)decryptString:(NSString *)srcString password:(NSString *)password error:(NSError **)error;

//对data进行加密
+ (NSData *)encryptData:(NSData *)srcData password:(NSString *)password error:(NSError **)error;
+ (NSData *)decryptData:(NSData *)srcData password:(NSString *)password error:(NSError **)error;

//对文件进行加密
+ (void)encryptFilePath:(NSString *)srcFilePath desFilePath:(NSString *)desFilePath password:(NSString *)password syncFlag:(BOOL)syncFlag completion:(KLCRyptorFileBlock)completion;
+ (void)decryptFilePath:(NSString *)srcFilePath desFilePath:(NSString *)desFilePath password:(NSString *)password syncFlag:(BOOL)syncFlag completion:(KLCRyptorFileBlock)completion;

@end

NS_ASSUME_NONNULL_END
