//
//  KLCryptorEngine.h
//  KLCryptor
//
//  Created by kevin on 2020/7/10.
//  Copyright © 2020 kevin. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

@interface KLCryptorEngine : NSObject

- (KLCryptorEngine *)initWithOperation:(CCOperation)operation alg:(CCAlgorithm)alg options:(CCOptions)options key:(NSData *)key IV:(NSData *)IV error:(NSError **)error;
- (NSData *)addData:(NSData *)data error:(NSError **)error;
- (NSData *)finishWithError:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
