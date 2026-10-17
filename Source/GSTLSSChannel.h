/** Private interface for the SChannel TLS implementation
   Copyright (C) 2026 Free Software Foundation, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 31 Milk Street #960789 Boston, MA 02196 USA.

   */

#ifndef _GSTLSSChannel_h_
#define _GSTLSSChannel_h_

#import "Foundation/NSObject.h"

@class  NSData;
@class  NSDictionary;
@class  NSString;

/* This mirrors the subset of the GNUTLS based GSTLSSession API which is
 * used internally by NSStream, NSFileHandle and NSSocketPort.
 * The options dictionary uses the GSTLS... keys declared in GSTLS.h,
 * except that GSTLSCertificateFile names a PKCS#12 (.pfx) file and
 * GSTLSCertificateKeyPassword is its password.
 */

extern NSString * const GSTLSVerifyFailedNotification;

typedef ssize_t (*GSTLSIOR)(void *, void *, size_t);
typedef ssize_t (*GSTLSIOW)(void *, const void *, size_t);

@interface      GSTLSObject : NSObject
+ (NSData*) dataForTLSFile: (NSString*)fileName;
+ (void) setData: (NSData*)data forTLSFile: (NSString*)fileName;
@end

@class  GSTLSCredentials;

@interface      GSTLSSession : GSTLSObject
{
  NSDictionary          *opts;
  GSTLSCredentials      *credentials;
  NSString              *problem;
  NSString              *issuer;
  NSString              *owner;
  BOOL                  outgoing;
  BOOL                  active;
  BOOL                  handshake;
  BOOL                  setup;
  BOOL                  debug;
  NSTimeInterval        created;
  void                  *handle;
  GSTLSIOW              pushFunc;
  GSTLSIOR              pullFunc;
  void                  *state;
}
- (id) initWithOptions: (NSDictionary*)options
             direction: (BOOL)isOutgoing
             transport: (void*)ioHandle
                  push: (GSTLSIOW)push
                  pull: (GSTLSIOR)pull;
- (BOOL) active;
- (NSTimeInterval) age;
- (BOOL) disconnect: (BOOL)reusable;
- (BOOL) handshake;
- (NSString*) issuer;
- (NSString*) owner;
- (size_t) pending;
- (NSString*) problem;
- (NSInteger) read: (void*)buf length: (NSUInteger)len;
- (NSString*) sessionInfo;
- (NSInteger) write: (const void*)buf length: (NSUInteger)len;
@end

#endif
