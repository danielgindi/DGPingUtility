//
//  DGPingUtility.m
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

#import "DGPingUtility.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <mach/mach_time.h>

#pragma mark - ICMP code/type macros

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO           8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

static uint16_t in_cksum(const void *buffer, size_t bufferLen);

#pragma mark - DGPingUtility

NSString * const kDGPingUtilityErrorCodeDomain = @"DGPingUtilityErrorCode";

@interface DGPingUtility ()

@property (nonatomic, assign, readwrite) uint16_t nextSequenceNumber;

- (void)stopHostResolution;
- (void)stopDataTransfer;

@end

@implementation DGPingUtility
{
    CFHostRef _host;
    CFSocketRef _socket;
    NSMutableDictionary *_pingSequenceStartTime;
    NSMutableDictionary *_pingSequenceTimer;
    NSObject *_pingSyncObject;
}

#pragma mark Lifecycle

- (id)initWithHostName:(NSString *)hostName address:(NSData *)hostAddress
{
    assert( (hostName != nil) == (hostAddress == nil) );
    self = [super init];
    if (self != nil)
    {
        self->_hostName = [hostName copy];
        self->_hostAddress = [hostAddress copy];
        self->_identifier = (uint16_t) arc4random();
        self->_pingSequenceStartTime = [NSMutableDictionary dictionary];
        self->_pingSequenceTimer = [NSMutableDictionary dictionary];
        self->_timeout = 1.0;
        self->_ttl = 49;
        self->_pingSyncObject = [[NSObject alloc] init];
    }
    return self;
}

- (id)initWithHostName:(NSString *)hostName
{
    return [self initWithHostName:hostName address:nil];
}

- (id)initWithHostAddress:(NSData *)hostAddress
{
    return [self initWithHostName:nil address:hostAddress];
}

- (void)dealloc
{
    [self stop];
}

+ (DGPingUtility *)pingUtilityWithHostName:(NSString *)hostName address:(NSData *)hostAddress
{
    return [[DGPingUtility alloc] initWithHostName:hostName address:hostAddress];
}

+ (DGPingUtility *)pingUtilityWithHostName:(NSString *)hostName
{
    return [[DGPingUtility alloc] initWithHostName:hostName address:nil];
}

+ (DGPingUtility *)pingUtilityWithHostAddress:(NSData *)hostAddress
{
    return [[DGPingUtility alloc] initWithHostName:nil address:hostAddress];
}

#pragma mark Error handling

/** @brief Calls -stop to stop and release, and then sends a -pingUtility:didFailWithError:error delegate callback */
- (void)didFailWithError:(NSError *)error
{
    [self stop];
    
    id<DGPingUtilityDelegate> delegate = self.delegate;
    if (delegate && [delegate respondsToSelector:@selector(pingUtility:didFailWithError:)])
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [delegate pingUtility:self didFailWithError:error];
        });
    }
}

/** @brief Converts the CFStreamError to an NSError and passes on to -didFailWithError: */
- (void)didFailWithHostStreamError:(CFStreamError)streamError
{
    NSDictionary *userInfo;
    NSError *error;

    if (streamError.domain == kCFStreamErrorDomainNetDB)
    {
        userInfo = @{ (NSString *)kCFGetAddrInfoFailureKey: @(streamError.error) };
    }
    else
    {
        userInfo = nil;
    }
    
    error = [NSError errorWithDomain:(NSString *)kCFErrorDomainCFNetwork code:kCFHostErrorUnknown userInfo:userInfo];

    [self didFailWithError:error];
}

#pragma Host resolution

static void HostResolveCallback(__unused CFHostRef theHost, __unused CFHostInfoType typeInfo, const CFStreamError *error, void *info)
{
    DGPingUtility *obj;
    
    obj = (__bridge DGPingUtility *) info;
    
    assert([obj isKindOfClass:[DGPingUtility class]]);
    assert(theHost == obj->_host);
    assert(typeInfo == kCFHostAddresses);
    
    if ( (error != NULL) && (error->domain != 0) )
    {
        [obj didFailWithHostStreamError:*error];
    }
    else
    {
        [obj hostResolutionDone];
    }
}

- (void)hostResolutionDone
{
    Boolean resolved;
    NSArray *addresses;
    
    // Find the first IPv4 address.
    
    addresses = (__bridge NSArray *) CFHostGetAddressing(self->_host, &resolved);
    if ( resolved && (addresses != nil) )
    {
        resolved = false;
        for (NSData * address in addresses)
        {
            const struct sockaddr * addrPtr;
            
            addrPtr = (const struct sockaddr *) [address bytes];
            if ( (address.length >= sizeof(struct sockaddr) && addrPtr->sa_family == AF_INET) /*||
                (address.length >= sizeof(struct sockaddr_in6) && addrPtr->sa_family == AF_INET6)*/ )
            {
                self.hostAddress = address;
                resolved = true;
                break;
            }
        }
    }
    
    // We're done resolving, so shut that down.
    
    [self stopHostResolution];
    
    // If all is OK, start pinging, otherwise shut down the pinger completely.
    
    if (resolved)
    {
        [self startWithHostAddress];
    }
    else
    {
        [self didFailWithError:[NSError errorWithDomain:(NSString *)kCFErrorDomainCFNetwork code:kCFHostErrorHostNotFound userInfo:nil]];
    }
}

- (void)startHostResolution
{
    [self stopHostResolution];
    
    Boolean success;
    CFHostClientContext context = {0, (__bridge void *)(self), NULL, NULL, NULL};
    CFStreamError streamError;
    
    assert(self->_host == NULL);
    
    self->_host = CFHostCreateWithName(NULL, (__bridge CFStringRef) self.hostName);
    assert(self->_host != NULL);
    
    CFHostSetClient(self->_host, HostResolveCallback, &context);
    
    CFHostScheduleWithRunLoop(self->_host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    
    success = CFHostStartInfoResolution(self->_host, kCFHostAddresses, &streamError);
    if ( ! success )
    {
        [self didFailWithHostStreamError:streamError];
    }
}

- (void)stopHostResolution
{
    if (self->_host)
    {
        CFHostSetClient(self->_host, NULL, NULL);
        CFHostUnscheduleFromRunLoop(self->_host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        CFRelease(self->_host);
        self->_host = NULL;
    }
}

#pragma mark Start / Stop

- (void)start
{
    @synchronized(_pingSyncObject)
    {
        if (self->_hostAddress)
        {
            [self startWithHostAddress];
        }
        else
        {
            [self startHostResolution];
        }
    }
}

- (void)stopDataTransfer
{
    if (self->_socket)
    {
        CFSocketInvalidate(self->_socket);
        CFRelease(self->_socket);
        self->_socket = NULL;
    }
}

- (void)stopTimers
{
    @synchronized(_pingSequenceTimer)
    {
        for (NSTimer *timer in _pingSequenceTimer.allValues)
        {
            [timer invalidate];
        }
        [_pingSequenceTimer removeAllObjects];
    }
}

- (void)stop
{
    @synchronized(_pingSyncObject)
    {
        [self stopHostResolution];
        [self stopDataTransfer];
        [self stopTimers];
    }
}

- (BOOL)isReady
{
    return self->_socket != NULL;
}

#pragma Sending a ping

- (void)startWithHostAddress
{
    int err;
    int fd;
    const struct sockaddr *addrPtr;
    
    assert(self.hostAddress != nil);
    
    // Open the socket.
    
    addrPtr = (const struct sockaddr *) self.hostAddress.bytes;
    
    fd = -1;
    err = 0;
    switch (addrPtr->sa_family)
    {
        case AF_INET:
            fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
            if (fd < 0)
            {
                err = errno;
            }
            break;
        case AF_INET6:
            /*fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
            if (fd < 0)
            {
                err = errno;
            }
            break;*/
            // IPv6 not supported yet, fallthrough
        default:
            err = EPROTONOSUPPORT;
            break;
    }
    
    if (err != 0)
    {
        [self didFailWithError:[NSError errorWithDomain:NSPOSIXErrorDomain code:err userInfo:nil]];
    }
    else
    {
        CFSocketContext context = {0, (__bridge void *)(self), NULL, NULL, NULL};
        CFRunLoopSourceRef rls;
        
        // Wrap it in a CFSocket and schedule it on the runloop.
        
        self->_socket = CFSocketCreateWithNative(NULL, fd, kCFSocketReadCallBack, SocketReadCallback, &context);
        assert(self->_socket != NULL);
        
        // The socket will now take care of cleaning up our file descriptor.
        
        assert( CFSocketGetSocketFlags(self->_socket) & kCFSocketCloseOnInvalidate );
        fd = -1;
        
        rls = CFSocketCreateRunLoopSource(NULL, self->_socket, 0);
        assert(rls != NULL);
        
        CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
        
        CFRelease(rls);
        
        if (self.ttl)
        {
            NSUInteger ttl = self.ttl;
            ttl = MAX(MIN(ttl, (NSUInteger)255), (NSUInteger)1);
            u_char ttlForSockOpt = (u_char)ttl;
            setsockopt(CFSocketGetNative(self->_socket), IPPROTO_IP, IP_TTL, &ttlForSockOpt, sizeof(NSUInteger));
            setsockopt(CFSocketGetNative(self->_socket), IPPROTO_IP, IP_MULTICAST_TTL, &ttlForSockOpt, sizeof(NSUInteger));
        }
        
        id<DGPingUtilityDelegate> delegate = self.delegate;
        if (delegate && [delegate respondsToSelector:@selector(pingUtility:didStartWithAddress:)])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [delegate pingUtility:self didStartWithAddress:self.hostAddress];
            });
        }
    }
    assert(fd == -1);
}

- (void)sendPing
{
    [self sendPingWithData:nil];
}

- (void)sendPingWithData:(NSData *)data
{
    @synchronized(_pingSyncObject)
    {
        int err;
        NSData *payload;
        NSMutableData *packet;
        ICMPHeader *icmpPtr;
        ssize_t bytesSent;
        
        const uint16_t sequenceNumber = self.nextSequenceNumber;
        const NSNumber *sequenceNSNumber = @(sequenceNumber);
        
        // Increment the sequence number
        
        self.nextSequenceNumber += 1;
        
        // Construct the ping packet.
        
        payload = data;
        if (payload == nil)
        {
            payload = [[NSString stringWithFormat:@"%28zd bottles of beer on the wall", (ssize_t) 99 - (size_t) (sequenceNumber % 100) ] dataUsingEncoding:NSASCIIStringEncoding];
            assert(payload.length == 56);
        }
        
        packet = [NSMutableData dataWithLength:sizeof(*icmpPtr) + [payload length]];
        assert(packet != nil);
        
        icmpPtr = [packet mutableBytes];
        icmpPtr->type = ICMP_ECHO;
        icmpPtr->code = 0;
        icmpPtr->checksum = 0;
        icmpPtr->identifier = OSSwapHostToBigInt16(self.identifier);
        icmpPtr->sequenceNumber = OSSwapHostToBigInt16(sequenceNumber);
        memcpy(&icmpPtr[1], [payload bytes], [payload length]);
        
        // The IP checksum returns a 16-bit number that's already in correct byte order
        // (due to wacky 1's complement maths), so we just put it into the packet as a
        // 16-bit unit.
        
        icmpPtr->checksum = in_cksum([packet bytes], [packet length]);
        
        // Send the packet.
        
        if (self->_socket == NULL)
        {
            bytesSent = -1;
            err = EBADF;
        }
        else
        {
            bytesSent = sendto(
                               CFSocketGetNative(self->_socket),
                               [packet bytes],
                               [packet length],
                               0,
                               (struct sockaddr *) self.hostAddress.bytes,
                               (socklen_t) self.hostAddress.length
                               );
            err = 0;
            if (bytesSent < 0)
            {
                err = errno;
            }
        }
        
        // Record the ping time
        
        const uint64_t pingSendTime = mach_absolute_time();
        
        // Handle the results of the send.
        
        id<DGPingUtilityDelegate> delegate = self.delegate;
        
        if ( (bytesSent > 0) && (((NSUInteger) bytesSent) == packet.length) )
        {
            // Complete success.  Tell the client.
            
            if (delegate && [delegate respondsToSelector:@selector(pingUtility:didSendPacket:number:)])
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [delegate pingUtility:self didSendPacket:packet number:sequenceNumber];
                });
            }
        }
        else
        {
            NSError *error;
            
            // Some sort of failure.  Tell the client.
            
            if (err == 0)
            {
                err = ENOBUFS; // This is not a hugely descriptor error, alas.
            }
            
            error = [NSError errorWithDomain:NSPOSIXErrorDomain code:err userInfo:nil];
            
            if (delegate && [delegate respondsToSelector:@selector(pingUtility:didFailToSendPacket:number:error:)])
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [delegate pingUtility:self didFailToSendPacket:packet number:sequenceNumber error:error];
                });
            }
        }
        
        // Set up the timeout stuff
        
        @synchronized(_pingSequenceTimer)
        {
            _pingSequenceStartTime[sequenceNSNumber] = @(pingSendTime);
            _pingSequenceTimer[sequenceNSNumber] = [NSTimer scheduledTimerWithTimeInterval:self.timeout target:self selector:@selector(pingTimeout:) userInfo:sequenceNSNumber repeats:NO];
        }
    }
}

- (void)pingTimeout:(NSNumber *)sequenceNumber
{
    @synchronized(_pingSequenceTimer)
    {
        // Does this timer still exist? If not, the packet has been handled already
        if (_pingSequenceTimer[sequenceNumber])
        {
            // Remove this timer
            [_pingSequenceTimer removeObjectForKey:sequenceNumber];
            
            id<DGPingUtilityDelegate> delegate = self.delegate;
            if (delegate && [delegate respondsToSelector:@selector(pingUtility:didTimeoutForPacketWithSequenceNumber:)])
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [delegate pingUtility:self didTimeoutForPacketWithSequenceNumber:[sequenceNumber unsignedShortValue]];
                });
            }
        }
    }
}

- (BOOL)isValidPingResponsePacket:(NSMutableData *)packet
{
    BOOL result;
    NSUInteger icmpHeaderOffset;
    ICMPHeader *icmpPtr;
    uint16_t receivedChecksum;
    uint16_t calculatedChecksum;
    
    result = NO;
    
    icmpHeaderOffset = [[self class] icmpHeaderOffsetInPacket:packet];
    if (icmpHeaderOffset != NSNotFound)
    {
        icmpPtr = (ICMPHeader *) (((uint8_t *)[packet mutableBytes]) + icmpHeaderOffset);
        
        receivedChecksum   = icmpPtr->checksum;
        icmpPtr->checksum  = 0;
        calculatedChecksum = in_cksum(icmpPtr, packet.length - icmpHeaderOffset);
        icmpPtr->checksum  = receivedChecksum;
        
        if (receivedChecksum == calculatedChecksum)
        {
            if ( (icmpPtr->type == ICMP_ECHOREPLY) && (icmpPtr->code == 0) )
            {
                if ( OSSwapBigToHostInt16(icmpPtr->identifier) == self.identifier )
                {
                    result = YES;
                }
            }
        }
    }
    
    return result;
}

/**
 @discussion This C routine is called by CFSocket when there's data waiting on our ICMP socket.
 It just redirects the call to Objective-C code.
 */
static void SocketReadCallback(__unused CFSocketRef s, __unused CFSocketCallBackType type, __unused CFDataRef address, __unused const void *data, void *info)
{
    DGPingUtility *obj;
    
    obj = (__bridge DGPingUtility *) info;
    assert([obj isKindOfClass:[DGPingUtility class]]);
    
    assert(s == obj->_socket);
    assert(type == kCFSocketReadCallBack);
    assert(address == nil);
    assert(data == nil);
    
    [obj readData];
}

- (void)readData
{
    int err;
    struct sockaddr_storage addr;
    socklen_t addrLen;
    ssize_t bytesRead;
    void * buffer;
    static const int kBufferSize = 65535;
    
    // Record the ping arrival time
    
    const uint64_t pingArrivalTime = mach_absolute_time();
    
    // 65535 is the maximum IP packet size, which seems like a reasonable bound
    // here (plus it's what <x-man-page://8/ping> uses).
    
    buffer = malloc(kBufferSize);
    assert(buffer != NULL);
    
    // Actually read the data.
    
    addrLen = sizeof(addr);
    bytesRead = recvfrom(CFSocketGetNative(self->_socket), buffer, kBufferSize, 0, (struct sockaddr *) &addr, &addrLen);
    err = 0;
    if (bytesRead < 0)
    {
        err = errno;
    }
    
    // Process the data we read.
    
    if (bytesRead > 0)
    {
        NSMutableData *packet;
        
        packet = [NSMutableData dataWithBytes:buffer length:(NSUInteger) bytesRead];
        assert(packet != nil);
        
        // We got some data, pass it up to our client.
        
        const IPHeader *ipHeaderPtr = (IPHeader *)packet.bytes;
        const ICMPHeader *icmpPtr = [DGPingUtility icmpInPacket:packet];
        
        id<DGPingUtilityDelegate> delegate = self.delegate;
        if ( [self isValidPingResponsePacket:packet] )
        {
            // Calculate ping duration from sent to received
            
            const uint16_t receivedSequenceNumber = OSSwapBigToHostInt16(icmpPtr->sequenceNumber);
            const NSNumber *receivedSequenceNSNumber = @(receivedSequenceNumber);
            const uint64_t pingSendTime = [_pingSequenceStartTime[receivedSequenceNSNumber] unsignedLongLongValue];
        
            mach_timebase_info_data_t mtuInfo = { 0, 0 };
            mach_timebase_info(&mtuInfo);
            const double pingDuration = ((double)(pingArrivalTime - pingSendTime) * (double)mtuInfo.numer / (double)mtuInfo.denom) / 1.0e9;
            
            // Check for timeout
            
            const BOOL didTimeout = pingDuration >= self.timeout;
            
            @synchronized(_pingSequenceTimer)
            {
                if (_pingSequenceTimer[receivedSequenceNSNumber])
                {
                    // Remove this timer
                    [_pingSequenceTimer removeObjectForKey:receivedSequenceNSNumber];
                    
                    if (didTimeout)
                    {
                        if (delegate && [delegate respondsToSelector:@selector(pingUtility:didTimeoutForPacketWithSequenceNumber:)])
                        {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [delegate pingUtility:self didTimeoutForPacketWithSequenceNumber:receivedSequenceNumber];
                            });
                        }
                    }
                }
                
                [_pingSequenceStartTime removeObjectForKey:receivedSequenceNSNumber];
            }
            
            // Send packet to delegate
            
            if (didTimeout)
            {
                if (delegate && [delegate respondsToSelector:@selector(pingUtility:didReceiveInvalidPacket:error:)])
                {
                    NSError *error = [NSError errorWithDomain:kDGPingUtilityErrorCodeDomain
                                                         code:DGPingUtilityErrorCodeTimeout
                                                     userInfo:@{ @"duration": @(pingDuration), @"ttl": @(ipHeaderPtr->timeToLive) }];
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [delegate pingUtility:self didReceiveInvalidPacket:packet error:error];
                    });
                }
            }
            else
            {
                if (delegate && [delegate respondsToSelector:@selector(pingUtility:didReceivePingResponsePacket:number:time:ttl:)])
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [delegate pingUtility:self didReceivePingResponsePacket:packet number:receivedSequenceNumber time:pingDuration ttl:ipHeaderPtr->timeToLive];
                    });
                }
            }
        }
        else
        {
            DGPingUtilityErrorCode errorCode = DGPingUtilityErrorCodeUnknown;
            
            if (packet.length >= sizeof(IPHeader) + sizeof(ICMPHeader))
            {
                if (icmpPtr->type == ICMP_ECHOREPLY && icmpPtr->identifier != self.identifier)
                {
                    errorCode = DGPingUtilityErrorCodePacketBelongsToSomeoneElse;
                }
                else
                {
                    switch (icmpPtr->type)
                    {
                        case ICMP_TIME_EXCEEDED:
                        {
                            switch(icmpPtr->code)
                            {
                                case ICMP_EXC_TTL: errorCode = DGPingUtilityErrorCodeTimeToLiveExceeded; break;
                                case ICMP_EXC_FRAGTIME: errorCode = DGPingUtilityErrorCodeFragReassemblyTimeExceeded; break;
                                default: break;
                            }
                        }
                            break;
                        case ICMP_DEST_UNREACH:
                        {
                            switch(icmpPtr->code)
                            {
                                case ICMP_NET_UNREACH: errorCode = DGPingUtilityErrorCodeDestinationNetUnreachable; break;
                                case ICMP_HOST_UNREACH: errorCode = DGPingUtilityErrorCodeDestinationHostUnreachable; break;
                                case ICMP_PROT_UNREACH: errorCode = DGPingUtilityErrorCodeDestinationProtocolUnreachable; break;
                                case ICMP_PORT_UNREACH: errorCode = DGPingUtilityErrorCodeDestinationPortUnreachable; break;
                                case ICMP_FRAG_NEEDED: errorCode = DGPingUtilityErrorCodeFragNeededAndDFSet; break;
                                case ICMP_SR_FAILED: errorCode = DGPingUtilityErrorCodeSourceRouteFailed; break;
                                case ICMP_NET_UNKNOWN: errorCode = DGPingUtilityErrorCodeDestinationFNetworkUnknown; break;
                                case ICMP_HOST_UNKNOWN: errorCode = DGPingUtilityErrorCodeDestinationFHostUnknown; break;
                                case ICMP_HOST_ISOLATED: errorCode = DGPingUtilityErrorCodeDestinationFHostIsolated; break;
                                case ICMP_NET_UNR_TOS: errorCode = DGPingUtilityErrorCodeDestinationNetworkUnreachableAtThisTOS; break;
                                case ICMP_HOST_UNR_TOS: errorCode = DGPingUtilityErrorCodeDestinationHostUnreachableAtThisTOS; break;
                                case ICMP_PKT_FILTERED: errorCode = DGPingUtilityErrorCodePacketFiltered; break;
                                case ICMP_PREC_VIOLATION: errorCode = DGPingUtilityErrorCodePrecedenceViolation; break;
                                case ICMP_PREC_CUTOFF: errorCode = DGPingUtilityErrorCodePrecedenceCutoff; break;
                                default: break;
                            }
                        }
                            break;
                        case ICMP_SOURCE_QUENCH: errorCode = DGPingUtilityErrorCodeSourceQuench; break;
                            
                        default: break;
                    }
                }
            }
            
            if (delegate && [delegate respondsToSelector:@selector(pingUtility:didReceiveInvalidPacket:error:)])
            {
                NSError *error = [NSError errorWithDomain:kDGPingUtilityErrorCodeDomain code:errorCode userInfo:nil];
                dispatch_async(dispatch_get_main_queue(), ^{
                    [delegate pingUtility:self didReceiveInvalidPacket:packet error:error];
                });
            }
        }
    }
    else
    {
        // We failed to read the data, so shut everything down.
        
        if (err == 0)
        {
            err = EPIPE;
        }
        
        [self didFailWithError:[NSError errorWithDomain:NSPOSIXErrorDomain code:err userInfo:nil]];
    }
    
    free(buffer);
    
    // Note that we don't loop back trying to read more data.
    // Rather, we just let CFSocket call us again.
}

#pragma Helpers

+ (NSUInteger)icmpHeaderOffsetInPacket:(NSData *)packet
{
    NSUInteger result;
    const struct IPHeader *ipPtr;
    size_t ipHeaderLength;
    
    result = NSNotFound;
    if (packet.length >= (sizeof(IPHeader) + sizeof(ICMPHeader)))
    {
        ipPtr = (const IPHeader *) packet.bytes;
        assert((ipPtr->versionAndHeaderLength & 0xF0) == 0x40);     // IPv4
        assert(ipPtr->protocol == 1);                               // ICMP
        ipHeaderLength = (ipPtr->versionAndHeaderLength & 0x0F) * sizeof(uint32_t);
        if (packet.length >= (ipHeaderLength + sizeof(ICMPHeader)))
        {
            result = ipHeaderLength;
        }
    }
    return result;
}

+ (const struct ICMPHeader *)icmpInPacket:(NSData *)packet
{
    const ICMPHeader *result;
    NSUInteger icmpHeaderOffset;
    
    result = nil;
    icmpHeaderOffset = [self icmpHeaderOffsetInPacket:packet];
    if (icmpHeaderOffset != NSNotFound)
    {
        result = (const ICMPHeader *) (((const uint8_t *)packet.bytes) + icmpHeaderOffset);
    }
    return result;
}

#pragma mark - C Helpers

// Standard checksum function taken from Apple's sample code
static uint16_t in_cksum(const void *buffer, size_t bufferLen)
{
    size_t              bytesLeft;
    int32_t             sum;
    const uint16_t *    cursor;
    union {
        uint16_t        us;
        uint8_t         uc[2];
    } last;
    uint16_t            answer;
    
    bytesLeft = bufferLen;
    sum = 0;
    cursor = buffer;
    
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (bytesLeft > 1)
    {
        sum += *cursor;
        cursor += 1;
        bytesLeft -= 2;
    }
    
    /* mop up an odd byte, if necessary */
    if (bytesLeft == 1)
    {
        last.uc[0] = * (const uint8_t *) cursor;
        last.uc[1] = 0;
        sum += last.us;
    }
    
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = (uint16_t) ~sum;   /* truncate to 16 bits */
    
    return answer;
}

@end
