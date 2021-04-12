//
//  KLAESCryptor.m
//  ComCryptor
//
//  Created by kevin on 2020/7/8.
//  Copyright © 2020 kevin. All rights reserved.
//

#import "KLAESCryptor.h"
#import <CommonCrypto/CommonCryptor.h>
#import "KLCryptorEngine.h"

NSString const *ivString = @"A-16-Byte-String";

typedef void (^KLCryptorHandler)(KLAESCryptor *cryptor, NSData *data);

@interface KLAESCryptor ()

@property (nonatomic, strong) NSError *error;
@property (nonatomic, getter=isFinished) BOOL finished;
@property (nonatomic, copy) KLCryptorHandler handler;

@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) NSMutableData *outData;

@property (nonatomic, strong) KLCryptorEngine *engine;

@end

@implementation KLAESCryptor

//生成AESKEY
+ (NSString *)generateAesKeyWithLength:(NSInteger)length
{
    unsigned char keyBytes[length/2];
    int result = SecRandomCopyBytes(kSecRandomDefault, length/2, keyBytes);
    if (result == 0){
        NSMutableString *keyStr = [NSMutableString new];
        for (int i=0; i<length/2; i++){
            [keyStr appendFormat:@"%02x", keyBytes[i]];
        }
        return keyStr;
    }
    return nil;
    
}

+ (NSString *)encryptString:(NSString *)srcString password:(NSString *)password error:(NSError **)error
{
    NSCParameterAssert(srcString);
    NSCParameterAssert(password);
    
    NSData *srcData = [srcString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *desData = [self cryptOperation:kCCEncrypt srcData:srcData password:password error:error];
    return [desData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
}

+ (NSString *)decryptString:(NSString *)srcString password:(NSString *)password error:(NSError **)error
{
    NSCParameterAssert(srcString);
    NSCParameterAssert(password);
    
    NSData *srcData = [[NSData alloc] initWithBase64EncodedString:srcString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *desData = [self cryptOperation:kCCDecrypt srcData:srcData password:password error:error];
    return [[NSString alloc] initWithData:desData encoding:NSUTF8StringEncoding];
}


+ (NSData *)encryptData:(NSData *)srcData password:(NSString *)password error:(NSError **)error
{
    NSCParameterAssert(srcData);
    NSCParameterAssert(password);
    
    return [self cryptOperation:kCCEncrypt srcData:srcData password:password error:error];
}

+ (NSData *)decryptData:(NSData *)srcData password:(NSString *)password error:(NSError **)error
{
    NSCParameterAssert(srcData);
    NSCParameterAssert(password);
    
    return [self cryptOperation:kCCDecrypt srcData:srcData password:password error:error];
}


+ (void)encryptFilePath:(NSString *)srcFilePath desFilePath:(NSString *)desFilePath password:(NSString *)password syncFlag:(BOOL)syncFlag completion:(KLCRyptorFileBlock)completion
{
    int blockSize = 32 * 1024;
    NSInputStream *srcStream = [NSInputStream inputStreamWithFileAtPath:srcFilePath];
    NSOutputStream *desStream = [NSOutputStream outputStreamToFileAtPath:desFilePath append:NO];
    
    [srcStream open];
    [desStream open];
    
    __block NSMutableData *data = [NSMutableData dataWithLength:blockSize];
    __block KLAESCryptor *crypto = nil;
    
    dispatch_semaphore_t sem;
    if (syncFlag){
        sem = dispatch_semaphore_create(0);
    }
    
    dispatch_block_t readSteamBloack = ^{
        [data setLength:blockSize];
        NSInteger bytesRead = [srcStream read:[data mutableBytes] maxLength:blockSize];
        if (bytesRead < 0){
            
        }else if (bytesRead == 0){
            [crypto finish];
        }else{
            [data setLength:bytesRead];
            [crypto addData:data];
        }
    };
    
    crypto = [[KLAESCryptor alloc] initWithOperation:kCCEncrypt password:password hanler:^(KLAESCryptor *crypto, NSData *data) {
        [desStream write:data.bytes maxLength:data.length];
        if (crypto.isFinished){
            [desStream close];
            if (syncFlag && sem) dispatch_semaphore_signal(sem);
        }else {
            readSteamBloack();
        }
    }];
    readSteamBloack();
    
    if (syncFlag && sem) dispatch_wait(sem, DISPATCH_TIME_FOREVER);
}

+ (void)decryptFilePath:(NSString *)srcFilePath desFilePath:(NSString *)desFilePath password:(NSString *)password syncFlag:(BOOL)syncFlag completion:(KLCRyptorFileBlock)completion
{
    int blockSize = 32 * 1024;
    NSInputStream *srcStream = [NSInputStream inputStreamWithFileAtPath:srcFilePath];
    NSOutputStream *desStream = [NSOutputStream outputStreamToFileAtPath:desFilePath append:NO];
    
    [srcStream open];
    [desStream open];
    
    __block NSMutableData *data = [NSMutableData dataWithLength:blockSize];
    __block KLAESCryptor *crypto = nil;
    
    dispatch_semaphore_t sem;
    if (syncFlag){
        sem = dispatch_semaphore_create(0);
    }
    
    dispatch_block_t readSteamBloack = ^{
        [data setLength:blockSize];
        NSInteger bytesRead = [srcStream read:[data mutableBytes] maxLength:blockSize];
        if (bytesRead < 0){
            
        }else if (bytesRead == 0){
            [crypto finish];
        }else{
            [data setLength:bytesRead];
            [crypto addData:data];
        }
    };
    
    crypto = [[KLAESCryptor alloc] initWithOperation:kCCDecrypt password:password hanler:^(KLAESCryptor *crypto, NSData *data) {
        [desStream write:data.bytes maxLength:data.length];
        if (crypto.isFinished){
            [desStream close];
            if (syncFlag && sem) dispatch_semaphore_signal(sem);
        }else {
            readSteamBloack();
        }
    }];
    readSteamBloack();
    
    if (syncFlag && sem) dispatch_wait(sem, DISPATCH_TIME_FOREVER);
}


#pragma mark - 私有方法

+ (NSData *)cryptOperation:(CCOperation)operation srcData:(NSData *)srcData password:(NSString *)password error:(NSError **)error
{
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [ivString dataUsingEncoding:NSUTF8StringEncoding];
    
    size_t desDataBytesSize = srcData.length + kCCBlockSizeAES128;
    void *desDataBytes = malloc(desDataBytesSize);
    if (desDataBytes == NULL){
        *error = [[NSError alloc] initWithDomain:@"malloc fail" code:1 userInfo:nil];
        return nil;
    }
    size_t outSzie = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          passwordData.bytes,
                                          passwordData.length,
                                          ivData.bytes,
                                          srcData.bytes,
                                          srcData.length,
                                          desDataBytes,
                                          desDataBytesSize,
                                          &outSzie);
    if (cryptStatus == kCCSuccess){
        return [NSData dataWithBytesNoCopy:desDataBytes length:outSzie];
    }
    free(desDataBytes);
    desDataBytes = nil;
    *error = [[NSError alloc] initWithDomain:@"CCCrypt init fail" code:cryptStatus userInfo:nil];
    return nil;
}



- (instancetype)initWithOperation:(CCOperation)operation password:(NSString *)password hanler:(KLCryptorHandler)handler
{
    self = [self initWithHandler:handler];
    if (self){
        NSData *keyData = [password dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivData = [ivString dataUsingEncoding:NSUTF8StringEncoding];
        
        NSError *error;
        self.engine = [[KLCryptorEngine alloc] initWithOperation:operation alg:kCCAlgorithmAES options:kCCOptionPKCS7Padding key:keyData IV:ivData error:&error];
        
        if (!self.engine) {
            [self cleanupAndNotifyWithError:error];
            return nil;
        }
    }
    return self;
}


- (id)initWithHandler:(KLCryptorHandler)handler
{
    NSParameterAssert(handler);
    
    self = [super init];
    if (self) {
        NSString *queueName = [@"kevin." stringByAppendingString:NSStringFromClass([self class])];
        _queue = dispatch_queue_create([queueName UTF8String], DISPATCH_QUEUE_SERIAL);
        
        _outData = [NSMutableData data];
        _handler = [handler copy];
    }
    return self;
}

- (void)addData:(NSData *)data
{
    if (self.isFinished) {
        return;
    }

  dispatch_async(self.queue, ^{
      NSError *error = nil;
      NSData *cryptedData = [self.engine addData:data error:&error];
      if (!cryptedData) {
          [self cleanupAndNotifyWithError:error];
      }
      [self.outData appendData:cryptedData];

      if (self.handler){
          self.handler(self, self.outData);
      }
      [self.outData setLength:0];
    });
}

- (void)cleanupAndNotifyWithError:(NSError *)error
{
    self.error = error;
    self.finished = YES;
    if (self.handler) {
        self.handler(self, self.outData);
        self.handler = nil;
    }
}

- (void)finish
{
    if (self.isFinished) {
        return;
    }

    dispatch_async(self.queue, ^{
        NSError *error = nil;
        NSData *cryptedData = [self.engine finishWithError:&error];
        [self.outData appendData:cryptedData];
      
        [self cleanupAndNotifyWithError:error];
    });
}

@end
