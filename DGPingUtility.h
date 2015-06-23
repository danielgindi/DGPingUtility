//
//  DGPingUtility.h
//
//  Created by Daniel Cohen Gindi on 5/8/13.
//  Copyright (c) 2013 danielgindi@gmail.com. All rights reserved.
//
//  https://github.com/danielgindi/DGPingUtility
//
//  The MIT License (MIT)
//
//  Copyright (c) 2015 Daniel Cohen Gindi (danielgindi@gmail.com)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

#import <Foundation/Foundation.h>

#if TARGET_OS_EMBEDDED || TARGET_IPHONE_SIMULATOR
    #import <CFNetwork/CFNetwork.h>
#else
    #import <CoreServices/CoreServices.h>
#endif

#include <AssertMacros.h>

#pragma mark - DGPingUtility

@protocol DGPingUtilityDelegate;

@interface DGPingUtility : NSObject

#pragma mark Constructors

- (id)initWithHostName:(NSString *)hostName address:(NSData *)hostAddress;
- (id)initWithHostName:(NSString *)hostName;
- (id)initWithHostAddress:(NSData *)hostAddress;

#pragma mark Convenience constructors

+ (DGPingUtility *)pingUtilityWithHostName:(NSString *)hostName address:(NSData *)hostAddress;
+ (DGPingUtility *)pingUtilityWithHostName:(NSString *)hostName;
+ (DGPingUtility *)pingUtilityWithHostAddress:(NSData *)hostAddress;

#pragma mark Properties

@property (nonatomic, weak, readwrite) id<DGPingUtilityDelegate> delegate;

/**
 @property isReady
 @brief is the pinger ready for pinging (socket open, address resolved)
 */
@property (nonatomic, assign, readonly) BOOL isReady;

/**
 @property hostName
 @brief the hostname. it will be resolved to an address if no address is specified.
 */
@property (nonatomic, strong) NSString *hostName;

/**
 @property hostAddress
 @brief a sockaddr/sockaddr_in6 struct
 */
@property (nonatomic, strong) NSData *hostAddress;

/** 
 @property identifier
 @brief the unique identifier for this ping 
 */
@property (nonatomic, assign, readonly) uint16_t identifier;

/** 
 @property nextSequenceNumber
 @brief the sequence number for the next ping to be sent 
 */
@property (nonatomic, assign, readonly) uint16_t nextSequenceNumber;

/** 
 @property timeout
 @brief default 1.0 seconds 
 */
@property (nonatomic, assign) NSTimeInterval timeout;

/** 
 @property ttl
 @brief default 255 (maximum 255) 
 */
@property (nonatomic, assign) NSUInteger ttl;

#pragma mark Core methods

/** 
 @brief Opens a socket for pinging. If the hostAddress is nil, then hostName is first resolved.
 */
- (void)start;

/**
 @brief Stops and releases any networking resources.
 */
- (void)stop;

/**
 @brief Sends an actual ping with the standard 56-byte payload resulting in a 64 byte ping.
 */
- (void)sendPingWithStandardPayload;

/**
 @brief Sends an actual ping with the associated payload.
 @param data Pass nil for a standard 56-byte payload resulting in a 64 byte ping. 
        Otherwise pass a non-nil value and it will be appended to the ICMP header.
 */
- (void)sendPingWithData:(NSData *)data;

#pragma mark Helpers

/**
 @return The address of the ICMP header that follows the IP header inside the packer. This doesn't do any significant validation of the packet.
 */
+ (const struct ICMPHeader *)icmpInPacket:(NSData *)packet;

@end

#pragma mark - DGPingUtilityDelegate

@protocol DGPingUtilityDelegate <NSObject>

@optional

/**
 @brief Called after the DGPingUtility has successfully started up.
 @discussion This generally means that an address has been resolved successfuly, and the socket is open.
 After this callback, you can start sending pings.
 */
- (void)pingUtility:(DGPingUtility *)pinger didStartWithAddress:(NSData *)address;

/**
 @brief If this is called, the DGPingUtility object has failed.
 @discussion By the time this callback is called, the object has stopped (that is, you don't need to call -stop yourself).
 */
- (void)pingUtility:(DGPingUtility *)pinger didFailWithError:(NSError *)error;

/**
 @brief Called whenever the DGPingUtility object has successfully sent a ping packet.
 @discussion A sent packet does not contain an IPHeader, so the packet starts with the ICMP header.
 */
- (void)pingUtility:(DGPingUtility *)pinger didSendPacket:(NSData *)packet
            number:(uint16_t)sequenceNumber;

/**
 @brief Called whenever the DGPingUtility object has successfully sent a ping packet.
 @discussion A sent packet does not contain an IPHeader, so the packet starts with the ICMP header.
 */
- (void)pingUtility:(DGPingUtility *)pinger didFailToSendPacket:(NSData *)packet
            number:(uint16_t)sequenceNumber
             error:(NSError *)error;
    // Called whenever the DGPingUtility object tries and fails to send a ping packet.

/**
 @brief Called whenever the DGPingUtility object receives an ICMP packet that looks like a response to one of our pings (that is, has a valid ICMP checksum, has an identifier that matches our identifier, and has a sequence number in the range of sequence numbers that we've sent out).
 @discussion A received packet starts with an IPHeader, so you should call +icmpInPacket: to find the ICMP header's position inside the packet.
 */
- (void)pingUtility:(DGPingUtility *)pinger didReceivePingResponsePacket:(NSData *)packet
            number:(uint16_t)sequenceNumber
              time:(NSTimeInterval)time
               ttl:(NSUInteger)ttl;

/**
 @brief Called whenever the DGPingUtility object receives an invalid ICMP packet
 */
- (void)pingUtility:(DGPingUtility *)pinger didReceiveInvalidPacket:(NSData *)packet error:(NSError *)error;

/**
 @brief Called whenever a sent packet has been timed out. If the packet eventually comes back, -samplePing:didReceiveInvalidPacket:error: will be called.
 */
- (void)pingUtility:(DGPingUtility *)pinger didTimeoutForPacketWithSequenceNumber:(uint16_t)sequenceNumber;

@end

#pragma mark - IP and ICMP structures

typedef struct IPHeader
{
    uint8_t     versionAndHeaderLength;
    uint8_t     differentiatedServices;
    uint16_t    totalLength;
    uint16_t    identification;
    uint16_t    flagsAndFragmentOffset;
    uint8_t     timeToLive;
    uint8_t     protocol;
    uint16_t    headerChecksum;
    uint8_t     sourceAddress[4];
    uint8_t     destinationAddress[4];
    // options...
    // data...
} IPHeader;

check_compile_time(sizeof(IPHeader) == 20);
check_compile_time(offsetof(IPHeader, versionAndHeaderLength) == 0);
check_compile_time(offsetof(IPHeader, differentiatedServices) == 1);
check_compile_time(offsetof(IPHeader, totalLength) == 2);
check_compile_time(offsetof(IPHeader, identification) == 4);
check_compile_time(offsetof(IPHeader, flagsAndFragmentOffset) == 6);
check_compile_time(offsetof(IPHeader, timeToLive) == 8);
check_compile_time(offsetof(IPHeader, protocol) == 9);
check_compile_time(offsetof(IPHeader, headerChecksum) == 10);
check_compile_time(offsetof(IPHeader, sourceAddress) == 12);
check_compile_time(offsetof(IPHeader, destinationAddress) == 16);

// ICMP header structure:

typedef struct ICMPHeader
{
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;
    uint16_t    identifier;
    uint16_t    sequenceNumber;
    // data...
} ICMPHeader;

check_compile_time(sizeof(ICMPHeader) == 8);
check_compile_time(offsetof(ICMPHeader, type) == 0);
check_compile_time(offsetof(ICMPHeader, code) == 1);
check_compile_time(offsetof(ICMPHeader, checksum) == 2);
check_compile_time(offsetof(ICMPHeader, identifier) == 4);
check_compile_time(offsetof(ICMPHeader, sequenceNumber) == 6);

#pragma mark - Error codes

NSString * const kDGPingUtilityErrorCodeDomain;

typedef NS_ENUM(NSInteger, DGPingUtilityErrorCode)
{
    DGPingUtilityErrorCodeUnknown = 0,
    
    DGPingUtilityErrorCodeTimeout = 1,
    DGPingUtilityErrorCodePacketBelongsToSomeoneElse = 2,
    
    DGPingUtilityErrorCodeTimeToLiveExceeded = 10,
    DGPingUtilityErrorCodeFragReassemblyTimeExceeded = 11,
    
    DGPingUtilityErrorCodeDestinationNetUnreachable = 20,
    DGPingUtilityErrorCodeDestinationHostUnreachable = 21,
    DGPingUtilityErrorCodeDestinationProtocolUnreachable = 22,
    DGPingUtilityErrorCodeDestinationPortUnreachable = 23,
    DGPingUtilityErrorCodeFragNeededAndDFSet = 24,
    DGPingUtilityErrorCodeSourceRouteFailed = 25,
    DGPingUtilityErrorCodeDestinationFNetworkUnknown = 26,
    DGPingUtilityErrorCodeDestinationFHostUnknown = 27,
    DGPingUtilityErrorCodeDestinationFHostIsolated = 28,
    DGPingUtilityErrorCodeDestinationNetworkUnreachableAtThisTOS = 29,
    DGPingUtilityErrorCodeDestinationHostUnreachableAtThisTOS = 30,
    DGPingUtilityErrorCodePacketFiltered = 31,
    DGPingUtilityErrorCodePrecedenceViolation = 32,
    DGPingUtilityErrorCodePrecedenceCutoff = 33,
    
    DGPingUtilityErrorCodeSourceQuench = 40,
};
