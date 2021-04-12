//
//  KLCryptorEngine.m
//  KLCryptor
//
//  Created by kevin on 2020/7/10.
//  Copyright © 2020 kevin. All rights reserved.
//

#import "KLCryptorEngine.h"

@interface KLCryptorEngine ()
@property (nonatomic, assign) CCCryptorRef cryptor;
@property (nonatomic, strong) NSMutableData *buffer;
@end

@implementation KLCryptorEngine

- (KLCryptorEngine *)initWithOperation:(CCOperation)operation alg:(CCAlgorithm)alg options:(CCOptions)options key:(NSData *)key IV:(NSData *)IV error:(NSError **)error
{
    self = [super init];
    if (self) {
        CCCryptorStatus
            cryptorStatus = CCCryptorCreate(operation,
                                        alg,
                                        options,
                                        key.bytes,
                                        key.length,
                                        IV.bytes,
                                        &_cryptor);
        if (cryptorStatus != kCCSuccess || _cryptor == NULL) {
            if (error) {
                *error = [NSError errorWithDomain:@"kevin.klcryptoerror" code:cryptorStatus userInfo:nil];
            }
            return nil;
        }

        _buffer = [NSMutableData data];
    }
    return self;
}

- (void)dealloc
{
    if (_cryptor) {
        CCCryptorRelease(_cryptor);
    }
}

- (NSData *)addData:(NSData *)data error:(NSError **)error
{
    NSMutableData *buffer = self.buffer;
    [buffer setLength:CCCryptorGetOutputLength(self.cryptor, [data length], true)]; // We'll reuse the buffer in -finish

    size_t dataOutMoved;
    CCCryptorStatus
        cryptorStatus = CCCryptorUpdate(self.cryptor,       // cryptor
                                      data.bytes,      // dataIn
                                      data.length,     // dataInLength (verified > 0 above)
                                      buffer.mutableBytes,      // dataOut
                                      buffer.length, // dataOutAvailable
                                      &dataOutMoved);   // dataOutMoved

    if (cryptorStatus != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"kevin.klcryptoerror" code:cryptorStatus userInfo:nil];
        }
        return nil;
    }

    return [buffer subdataWithRange:NSMakeRange(0, dataOutMoved)];
}

- (NSData *)finishWithError:(NSError **)error
{
    NSMutableData *buffer = self.buffer;
    size_t dataOutMoved;
    CCCryptorStatus
        cryptorStatus = CCCryptorFinal(self.cryptor,        // cryptor
                                     buffer.mutableBytes,       // dataOut
                                     buffer.length,  // dataOutAvailable
                                     &dataOutMoved);    // dataOutMoved
    if (cryptorStatus != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"kevin.klcryptoerror" code:cryptorStatus userInfo:nil];
        }
        return nil;
    }

    return [buffer subdataWithRange:NSMakeRange(0, dataOutMoved)];
}


@end
