/** Implementation for GSTLS classes for GNUStep
   Copyright (C) 2012 Free Software Foundation, Inc.

   Written by:  Richard Frith-Macdonald <rfm@gnu.org>
   Date: 2101

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

#import "common.h"

#import "Foundation/NSArray.h"
#import "Foundation/NSBundle.h"
#import "Foundation/NSCharacterSet.h"
#import "Foundation/NSData.h"
#import "Foundation/NSDictionary.h"
#import "Foundation/NSEnumerator.h"
#import "Foundation/NSFileManager.h"
#import "Foundation/NSHost.h"
#import "Foundation/NSException.h"
#import "Foundation/NSLock.h"
#import "Foundation/NSNotification.h"
#import "Foundation/NSProcessInfo.h"
#import "Foundation/NSSet.h"
#import "Foundation/NSStream.h"
#import "Foundation/NSTask.h"
#import "Foundation/NSThread.h"
#import "Foundation/NSUserDefaults.h"
#import "Foundation/NSUUID.h"

#import "GNUstepBase/GSTLS.h"

#import "GSPrivate.h"

NSString* const GSTLSVerifyFailedNotification
  = @"GSTLSVerifyFailedNotification";

@interface	NSString(gnutlsFileSystemRepresentation)
- (const char*) gnutlsFileSystemRepresentation;
@end

@implementation	NSString(gnutlsFileSystemRepresentation)
- (const char*) gnutlsFileSystemRepresentation
{
#if	defined(_WIN32)
  const unichar	*buf = (const unichar*)[self fileSystemRepresentation];
  int		len = 0;
  NSString	*str;
  const char	*result;

  while (buf[len] > 0)
    {
      len++;
    }
  str = [[NSString alloc] initWithBytes: buf 
				 length: len * 2
			       encoding: NSUnicodeStringEncoding];
  result = [str UTF8String];
  RELEASE(str);
  return result;   
#else
  return [self fileSystemRepresentation];
#endif
}
@end

#if     defined(HAVE_GNUTLS) || defined(HAVE_SCHANNEL)

static NSString *
standardizedPath(NSString *path)
{
  if (0 == [path length])
    {
      return nil;       // Not a path
    }
  if (NO == [path isAbsolutePath])
    {
      path = [[[NSFileManager defaultManager] currentDirectoryPath]
        stringByAppendingPathComponent: path];
    }
  return [path stringByStandardizingPath];
}

#if     defined(HAVE_GNUTLS)
#if GNUTLS_VERSION_NUMBER <= 0x020b00
/* Set up locking callbacks for gcrypt so that it will be thread-safe.
 */
static int gcry_mutex_init(void **priv)
{
  NSLock        *lock = [NSLock new];
  *priv = (void*)lock;
  return 0;
}
static int gcry_mutex_destroy(void **lock)
{
  [((NSLock*)*lock) release];
  return 0;
}
static int gcry_mutex_lock(void **lock)
{
  [((NSLock*)*lock) lock];
  return 0;
}
static int gcry_mutex_unlock(void **lock)
{
  [((NSLock*)*lock) unlock];
  return 0;
}
static struct gcry_thread_cbs gcry_threads_other = {
  GCRY_THREAD_OPTION_DEFAULT,
  NULL,
  gcry_mutex_init,
  gcry_mutex_destroy,
  gcry_mutex_lock,
  gcry_mutex_unlock
};
#endif

static void
GSTLSLog(int level, const char *msg)
{
  NSLog(@"%s", msg);
}
#endif  /* HAVE_GNUTLS */

/* The caFile variable holds the location of the file containing the default
 * certificate authorities to be used by our system.
 * The hard-coded value is the GNUTLS system default set, with a fallback to
 * a file in the GSTLS folder of the base library resource bundle,
 * but this can be overridden by the GS_TLS_CA_FILE
 * environment variable, which in turn will be overridden by the GSTLSCAFile
 * user default string.
 */
static NSString *caFile = nil;          // GSTLS/ca-certificates.crt

/* The caRevoke variable holds the location of the file containing the default
 * certificate revocation list to be used by our system.
 * The hard-coded value is a file in the GSTLS folder of the base library
 * resource bundle, but this can be overridden by the GS_TLS_REVOKE
 * environment variable, which in turn will be overridden by the GSTLSRevokeFile
 * user default string.
 */
static NSString *revokeFile = nil;      // GSTLS/revoke.crl

/* The verifyClient variable tells us if connections from a remote server
 * should (by default) provide a client certificate which we verify against
 * our trusted authorities.
 * The hard-coded value can be overridden by the GS_TLS_VERIFY_C environment
 * variable, which in turn will be overridden by the GSTLSVerifyClient user
 * default string.
 * A GSTLSVerify option set for a specific session overrides this default
 */
static BOOL     verifyClient = NO;

/* The verifyServer variable tells us if outgoing connections (as a client)
 * to a remote server should (by default) verify that server's certificate
 * against our trusted authorities.
 * The hard-coded value can be overridden by the GS_TLS_VERIFY_S environment
 * variable, which in turn will be overridden by the GSTLSVerifyServer user
 * default string.
 * A GSTLSVerify option set for a specific session overrides this default
 */
static BOOL     verifyServer = YES;

/* The globalDebug variable turns on gnutls debug.  The hard-code value is
 * overridden by GS_TLS_DEBUG, which in turn can be overridden by the
 * GSTLSDebug user default. This is an integer debug level with higher
 * values producing more debug output.  Usually levels above 1 are too
 * verbose and not useful unless you have the gnutls source code to hand.
 * NB. The GSTLSDebug session option is a boolean to turn on extra debug for
 * a particular session to be produced on verification failure.
 */
static int      globalDebug = 0;

/* Defines the default priority list.
 */
static NSString *priority = nil;

#if     defined(HAVE_GNUTLS)
static gnutls_anon_client_credentials_t anoncred;
#else
static void GSTLSDeleteImportedKeys(void);
#endif

/* This class is used to ensure that the TLS system is initialised
 * and thread-safe.
 */
@implementation GSTLSObject

static NSLock                   *certificateListLock = nil;
static NSMutableDictionary      *certificateListCache = nil;

static NSLock                   *credentialsLock = nil;
static NSMutableDictionary      *credentialsCache = nil;

static NSLock                   *fileLock = nil;
static NSMutableDictionary      *fileMap = nil;

static NSLock                   *paramsLock = nil;
static NSMutableDictionary      *paramsCache = nil;

static NSLock                   *privateKeyLock = nil;
static NSMutableDictionary      *privateKeyCache0 = nil;
static NSMutableDictionary      *privateKeyCache1 = nil;

+ (void) _defaultsChanged: (NSNotification*)n
{
  NSBundle              *bundle;
  NSUserDefaults        *defs;
  NSDictionary          *env;
  NSString              *str;

  bundle = [NSBundle bundleForClass: [NSObject class]];
  defs = [NSUserDefaults standardUserDefaults];
  env = [[NSProcessInfo processInfo] environment];

  str = [defs stringForKey: @"GSCipherList"];
  if (nil != str)
    {
      GSOnceMLog(@"GSCipherList is no longer used, please try GSTLSPriority");
    }

  str = [defs stringForKey: GSTLSPriority];
  if (0 == [str length])
    {
      str = nil;        // nil or empty string resets to default
    }
  ASSIGN(priority, str);


  /* The GSTLSCAFile user default overrides the builtin value or the
   * GS_TLS_CA_FILE environment variable.
   */
  str = [defs stringForKey: GSTLSCAFile];
  if (nil == str)
    {
      /* Let the GS_TLS_CA_FILE environment variable override the
       * default certificate authority location.
       * Failing that, use the same environment variable as OpenSSL
       */
      str = [env objectForKey: @"GS_TLS_CA_FILE"];
      if (nil == str)
        {
          str = [env objectForKey: @"SSL_CERT_FILE"];
        }
    }
  str = standardizedPath(str);
  ASSIGN(caFile, str);

  /* The GSTLSRevokeFile user default overrides the builtin value or the
   * GS_TLS_REVOKE environment variable.
   */
  str = [defs stringForKey: GSTLSRevokeFile];
  if (nil == str)
    {
      /* Let the GS_TLS_REVOKE environment variable override the
       * default revocation list location.
       */
      str = [env objectForKey: @"GS_TLS_REVOKE"];
      if (nil == str)
        {
          str = [bundle pathForResource: @"revoke"
                                 ofType: @"crl"
                            inDirectory: @"GSTLS"];
        }
    }
  str = standardizedPath(str);
  ASSIGN(revokeFile, str);

  str = [defs stringForKey: @"GSTLSVerifyClient"];
  if (nil == str)
    {
      str = [env objectForKey: @"GS_TLS_VERIFY_C"];
    }
  if (str)
    {
      verifyClient = [str boolValue];
    }

  str = [defs stringForKey: @"GSTLSVerifyServer"];
  if (nil == str)
    { 
      str = [env objectForKey: @"GS_TLS_VERIFY_S"];
    }
  if (str)
    {
      verifyServer = [str boolValue];
    }

  str = [defs stringForKey: GSTLSDebug];
  if (nil == str)
    {
      str = [env objectForKey: @"GS_TLS_DEBUG"];
    }
  globalDebug = [str intValue];
  if (globalDebug < 0)
    {
      globalDebug = 0;
    }

#if     defined(HAVE_GNUTLS)
  gnutls_global_set_log_level(globalDebug);
#endif
}

+ (void) atExit
{
#if     defined(HAVE_SCHANNEL)
  /* Keys imported into the CNG key store must not outlive the process.
   */
  GSTLSDeleteImportedKeys();
#endif
  if ([NSObject shouldCleanUp])
    {
      DESTROY(certificateListLock);
      DESTROY(certificateListCache);
      DESTROY(credentialsLock);
      DESTROY(credentialsCache);
      DESTROY(fileLock);
      DESTROY(fileMap);
      DESTROY(paramsLock);
      DESTROY(paramsCache);
      DESTROY(privateKeyLock);
      DESTROY(privateKeyCache0);
      DESTROY(privateKeyCache1);
    }
}

+ (NSData*) dataForTLSFile: (NSString*)fileName
{
  NSData        *result;

  if (NO == [fileName isKindOfClass: [NSString class]])
    {
      [NSException raise: NSInvalidArgumentException
                  format: @"[GSTLS+dataForTLSFile:] called with bad file name"];
    }
  [fileLock lock];
  NS_DURING
    {
      result = [[fileMap objectForKey: fileName] retain];
    }
  NS_HANDLER
    {
      [fileLock unlock];
      result = nil;
      [localException raise];
    }
  NS_ENDHANDLER
  [fileLock unlock];
  if (nil == result)
    {
      return [NSData dataWithContentsOfFile: fileName];
    }
  return [result autorelease];
}

+ (void) initialize
{
  if ([GSTLSObject class] == self)
    {
      static BOOL   beenHere = NO;

      if (beenHere == NO)
        {
          beenHere = YES;

	  [self registerAtExit];

          fileLock = [NSLock new];
          fileMap = [NSMutableDictionary new];

          [[NSNotificationCenter defaultCenter]
            addObserver: self
               selector: @selector(_defaultsChanged:)
                   name: NSUserDefaultsDidChangeNotification
                 object: nil];

#if     defined(HAVE_GNUTLS)
#if GNUTLS_VERSION_NUMBER <= 0x020b00
          /* Make gcrypt thread-safe
           */
          gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_other);
#endif

          /* Initialise gnutls
           */
          gnutls_global_init();

          /* Allocate global credential information for anonymous tls
           */
          gnutls_anon_allocate_client_credentials(&anoncred);

          /* Enable gnutls logging via NSLog
           */
          gnutls_global_set_log_function(GSTLSLog);
#endif

          [self _defaultsChanged: nil];
        }
    }
}

+ (void) setData: (NSData*)data forTLSFile: (NSString*)fileName
{
  fileName = standardizedPath(fileName);
  if (nil != data && NO == [data isKindOfClass: [NSData class]])
    {
      [NSException raise: NSInvalidArgumentException
                  format: @"[GSTLS+setData:forTLSFile:] called with bad data"];
    }
  if (NO == [fileName isKindOfClass: [NSString class]])
    {
      [NSException raise: NSInvalidArgumentException
                  format: @"[GSTLS+setData:forTLSFile:] called with bad file"];
    }
  [fileLock lock];
  NS_DURING
    {
      if (data == nil)
        {
          [fileMap removeObjectForKey: fileName];
        }
      else
        {
          [fileMap setObject: data forKey: fileName];
        }
    }
  NS_HANDLER
    {
      [fileLock unlock];
      [localException raise];
    }
  NS_ENDHANDLER
  [fileLock unlock];
}

@end

#if     defined(HAVE_GNUTLS)

@implementation GSTLSDHParams
static NSTimeInterval           paramsWhen = 0.0;
static BOOL                     paramsGenerating = NO;
static GSTLSDHParams            *paramsCurrent = nil;

+ (GSTLSDHParams*) current
{
  GSTLSDHParams	*p; 
  
  [paramsLock lock];
  if (nil == paramsCurrent)
    {
      if (NO == paramsGenerating)
        {
          [paramsLock unlock];
          [self generate];
          [paramsLock lock];
        }
      while (nil == paramsCurrent)
        {
          [paramsLock unlock];
          [NSThread sleepForTimeInterval: 0.2];
          [paramsLock lock];
        }
    }
  p = [paramsCurrent retain];
  [paramsLock unlock];
  return [p autorelease];
}

+ (void) generate
{
  GSTLSDHParams         *p;

  [paramsLock lock];
  if (YES == paramsGenerating)
    {
      [paramsLock unlock];
      return;
    }
  paramsGenerating = YES;
  [paramsLock unlock];

  p = [GSTLSDHParams new];
  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters often.
   */
  gnutls_dh_params_init(&p->params);
  gnutls_dh_params_generate2 (p->params, 2048);
  [paramsLock lock];
  [paramsCurrent release];
  paramsCurrent = p;
  paramsWhen = [NSDate timeIntervalSinceReferenceDate];
  paramsGenerating = NO;
  [paramsLock unlock];
}

+ (void) housekeeping: (NSNotification*)n
{
  NSEnumerator          *enumerator;
  NSString              *key;
  NSTimeInterval        now;

  now = [NSDate timeIntervalSinceReferenceDate];
  [paramsLock lock];

  enumerator = [[paramsCache allKeys] objectEnumerator];
  while (nil != (key = [enumerator nextObject]))
    {
      GSTLSDHParams     *p;

      p = [paramsCache objectForKey: key];

      if (now - p->when > 300.0)
        {
          [paramsCache removeObjectForKey: key];
        }
    }

  /* Regenerate DH params once per day, perfoming generation in another
   * thread since it's likely to be rather slow.
   */
  if (nil != paramsCurrent && NO == paramsGenerating
    && paramsWhen > 24.0 * 60.0 * 60.0)
    {
      [NSThread detachNewThreadSelector: @selector(generate)
                               toTarget: self
                             withObject: nil];
    }
  [paramsLock unlock];
}

+ (void) initialize
{
  if (nil == paramsLock)
    {
      paramsLock = [NSLock new];
      paramsWhen = [NSDate timeIntervalSinceReferenceDate];
      paramsCache = [NSMutableDictionary new];
      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(housekeeping:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (GSTLSDHParams*) paramsFromFile: (NSString*)f
{
  GSTLSDHParams *p;

  if (nil == f)
    {
      return nil;
    }
  f = standardizedPath(f);
  [paramsLock lock];
  p = [[paramsCache objectForKey: f] retain];
  [paramsLock unlock];

  if (nil == p)
    {
      NSData                    *data;
      int                       ret;
      gnutls_datum_t            datum;

      data = [[self class] dataForTLSFile: f];
      if (nil == data)
        {
          NSLog(@"Unable to read DF params file '%@'", f);
          return nil;
        }
      datum.data = (unsigned char*)[data bytes];
      datum.size = (unsigned int)[data length];

      p = [self alloc];
      p->when = [NSDate timeIntervalSinceReferenceDate];
      p->path = [f copy];
      gnutls_dh_params_init(&p->params);
      ret = gnutls_dh_params_import_pkcs3(p->params, &datum,
        GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          NSLog(@"Unable to parse DH params file '%@': %s",
            p->path, gnutls_strerror(ret));
          [p release];
          return nil;
        }
      [paramsLock lock];
      [paramsCache setObject: p forKey: p->path];
      [paramsLock unlock];
    }

  return [p autorelease];
}

- (void) dealloc
{
  gnutls_dh_params_deinit(params);
  [super dealloc];
}

- (gnutls_dh_params_t) params
{
  return params;
}

@end

@implementation GSTLSCertificateList


+ (void) certInfo: (gnutls_x509_crt_t)cert to: (NSMutableString*)str
{
  gnutls_datum_t	dn = { 0, 0 };
  int           	ret;

  ret = gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &dn);
  if (0 == ret)
    {
      NSString	*tmp;

      tmp = [[NSString alloc] initWithBytesNoCopy: dn.data
					   length: dn.size
					 encoding: NSUTF8StringEncoding
				     freeWhenDone: YES];
      [str appendString: tmp];
      RELEASE(tmp);
    } 
  else 
    { 
      [str appendString: @"Unknown"];
      NSLog(@"-certInfo:to: failed with '%s'", gnutls_strerror(ret));
      if (dn.data) free(dn.data);
    }
}
 
/* Method to purge older lists from cache.
 */
+ (void) housekeeping: (NSNotification*)n
{
  NSEnumerator          *enumerator;
  NSString              *key;
  NSTimeInterval        now;

  now = [NSDate timeIntervalSinceReferenceDate];
  [certificateListLock lock];
  enumerator = [[certificateListCache allKeys] objectEnumerator];
  while (nil != (key = [enumerator nextObject]))
    {
      GSTLSCertificateList      *list;

      list = [certificateListCache objectForKey: key];

      if (now - list->when > 300.0)
        {
          [certificateListCache removeObjectForKey: key];
        }
    }
  [certificateListLock unlock];
}

+ (void) initialize
{
  if (nil == certificateListLock)
    {
      certificateListLock = [NSLock new];
      certificateListCache = [NSMutableDictionary new];
      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(housekeeping:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (GSTLSCertificateList*) listFromFile: (NSString*)f
{
  GSTLSCertificateList  *l;

  if (nil == f)
    {
      return nil;
    }
  f = standardizedPath(f);
  [certificateListLock lock];
  l = [[certificateListCache objectForKey: f] retain];
  [certificateListLock unlock];

  if (nil == l)
    {
      NSData                    *data;
      int                       ret;
      gnutls_datum_t            datum;
      unsigned int              count = 100;
      gnutls_x509_crt_t         crts[count];

      data = [[self class] dataForTLSFile: f];
      if (nil == data)
        {
          NSLog(@"Unable to read certificate file '%@'", f);
          return nil;
        }
      datum.data = (unsigned char*)[data bytes];
      datum.size = (unsigned int)[data length];

      l = [self alloc];
      l->when = [NSDate timeIntervalSinceReferenceDate];
      l->path = [f copy];
      ret = gnutls_x509_crt_list_import(crts, &count, &datum,
        GNUTLS_X509_FMT_PEM,
//            GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED |
        GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
      if (ret < 0)
        {
          NSLog(@"Unable to parse certificate file '%@': %s",
            l->path, gnutls_strerror(ret));
          [l release];
          return nil;
        }

      if (count > 0)
        {
          time_t        now = (time_t)[[NSDate date] timeIntervalSince1970];
          unsigned int  i;

          l->crts = malloc(sizeof(gnutls_x509_crt_t) * count);
          memcpy(l->crts, crts, sizeof(gnutls_x509_crt_t) * count);
          l->count = count;

          for (i = 0; i < count; i++)
            {
              time_t    expiret = gnutls_x509_crt_get_expiration_time(crts[i]);
              time_t    activet = gnutls_x509_crt_get_activation_time(crts[i]);

              if (expiret <= now)
                {
                  NSLog(@"WARNING: at index %u in %@ ... expired at %s",
                    i, l->path, ctime(&activet));
                }
              if (activet > now)
                {
                  NSLog(@"WARNING: at index %u in %@ ... not valid until %s",
                    i, l->path, ctime(&activet));
                }
              if (expiret <= now || activet > now)
                {
                  NSMutableString       *m;

                  m = [NSMutableString stringWithCapacity: 2000];
                  [self certInfo: crts[i] to: m];
                  NSLog(@"%@", m);
                }
            }
        }

      [certificateListLock lock];
      [certificateListCache setObject: l forKey: l->path];
      [certificateListLock unlock];
    }

  return [l autorelease];
}

- (gnutls_x509_crt_t*) certificateList
{
  return crts;
}

- (unsigned int) count
{
  return count;
}

- (NSDate*) expiresAt
{
  unsigned      index = count;
  time_t        expiret;

  if (index-- == 0)
    {
      return nil;
    }

  expiret = gnutls_x509_crt_get_expiration_time(crts[index]);
  if (expiret < 0)
    {
      return nil;
    }

  while (index > 0)
    {
      time_t    t = gnutls_x509_crt_get_expiration_time(crts[--index]);

      if (t < 0)
        {
          return nil;
        }
    
      if (t < expiret)
        {
          expiret = t;
        }
    }

  return [NSDate dateWithTimeIntervalSince1970: expiret];
}

- (NSDate*) expiresAt: (unsigned int)index
{
  time_t        expiret;

  if (count == 0 || index > count - 1)
    {
      return nil;
    }

  expiret = gnutls_x509_crt_get_expiration_time(crts[index]);

  if (expiret < 0)
    {
      return nil;
    }
  else
    {
      return [NSDate dateWithTimeIntervalSince1970: expiret];
    }
}

- (void) dealloc
{
  if (nil != path)
    {
      DESTROY(path);
      if (count > 0)
        {
          while (count-- > 0)
            {
              if (crts) gnutls_x509_crt_deinit(crts[count]);
            }
          if (crts) free(crts);
        }
    }
  [super dealloc];
}

@end


@implementation GSTLSPrivateKey


/* Method to purge older keys from cache.
 */
+ (void) housekeeping: (NSNotification*)n
{
  NSEnumerator          *outer;
  NSString              *oKey;
  NSTimeInterval        now;

  now = [NSDate timeIntervalSinceReferenceDate];
  [privateKeyLock lock];
  outer = [[privateKeyCache0 allKeys] objectEnumerator];
  while (nil != (oKey = [outer nextObject]))
    {
      GSTLSPrivateKey   *key;

      key = [privateKeyCache0 objectForKey: oKey];
      if (now - key->when > 300.0)
        {
          [privateKeyCache0 removeObjectForKey: oKey];
        }
    }
  outer = [[privateKeyCache1 allKeys] objectEnumerator];
  while (nil != (oKey = [outer nextObject]))
    {
      NSMutableDictionary       *m;
      NSEnumerator              *inner;
      NSString                  *iKey;

      m = [privateKeyCache1 objectForKey: oKey];
      inner = [[m allKeys] objectEnumerator];
      while (nil != (iKey = [inner nextObject]))
        {
          GSTLSPrivateKey       *key = [m objectForKey: iKey];

          if (now - key->when > 300.0)
            {
              [m removeObjectForKey: iKey];
              if (0 == [m count])
                {
                  [privateKeyCache1 removeObjectForKey: oKey];
                }
            }
        }
    }
  [privateKeyLock unlock];
}

+ (void) initialize
{
  if (nil == privateKeyLock)
    {
      privateKeyLock = [NSLock new];
      privateKeyCache0 = [NSMutableDictionary new];
      privateKeyCache1 = [NSMutableDictionary new];

      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(housekeeping:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (GSTLSPrivateKey*) keyFromFile: (NSString*)f withPassword: (NSString*)p
{
  GSTLSPrivateKey       *k;

  if (nil == f)
    {
      return nil;
    }
  f = standardizedPath(f);
  [privateKeyLock lock];
  if (nil == p)
    {
      k = [privateKeyCache0 objectForKey: f];
    }
  else
    {
      NSMutableDictionary       *m;

      m = [privateKeyCache1 objectForKey: f];
      if (nil == m)
        {
          k = nil;
        }
      else
        {
          k = [m objectForKey: p];
        }
    }
  [k retain];
  [privateKeyLock unlock];

  if (nil == k)
    {
      NSData                    *data;
      int                       ret;
      gnutls_datum_t            datum;

      data = [[self class] dataForTLSFile: f];
      if (nil == data)
        {
          NSLog(@"Unable to read private key file '%@'", f);
          return nil;
        }
      datum.data = (unsigned char*)[data bytes];
      datum.size = (unsigned int)[data length];

      k = [self alloc];
      k->when = [NSDate timeIntervalSinceReferenceDate];
      k->path = [f copy];
      k->password = [p copy];
      gnutls_x509_privkey_init(&k->key);

#ifdef HAVE_GNUTLS_X509_PRIVKEY_IMPORT2
      /* This function can read openssl proprietory key format,
       * and uses the password if supplied.
       */
      ret = gnutls_x509_privkey_import2(k->key, &datum,
        GNUTLS_X509_FMT_PEM, [k->password UTF8String], 0);
#else
      if (nil == k->password)
        {
          ret = gnutls_x509_privkey_import(k->key, &datum,
            GNUTLS_X509_FMT_PEM);
        }
      else
        {
          ret = gnutls_x509_privkey_import_pkcs8(k->key, &datum,
            GNUTLS_X509_FMT_PEM, [k->password UTF8String], 0);
        }
#endif

      if (ret < 0)
        {
          NSLog(@"Unable to parse private key file '%@': %s",
            k->path, gnutls_strerror(ret));
          [k release];
          return nil;
        }
      [privateKeyLock lock];
      if (nil == k->password)
        {
          [privateKeyCache0 setObject: k forKey: k->path];
        }
      else
        {
          NSMutableDictionary   *m;

          m = [privateKeyCache1 objectForKey: f];
          if (nil == m)
            {
              m = [NSMutableDictionary new];
              [privateKeyCache1 setObject: m forKey: f];
              [m release];
            }
          [m setObject: k forKey: p];
        }
      [privateKeyLock unlock];
    }

  return [k autorelease];
}

- (void) dealloc
{
  if (nil != path)
    {
      DESTROY(path);
      DESTROY(password);
      gnutls_x509_privkey_deinit(key);
    }
  [super dealloc];
}

- (gnutls_x509_privkey_t) key
{
  return key;
}
@end


@implementation GSTLSCredentials


/* Method to purge older credentials from cache.
 */
+ (void) housekeeping: (NSNotification*)n
{
  NSEnumerator          *enumerator;
  NSDictionary          *key;
  NSTimeInterval        now;

  now = [NSDate timeIntervalSinceReferenceDate];
  [credentialsLock lock];
  enumerator = [[credentialsCache allKeys] objectEnumerator];
  while (nil != (key = [enumerator nextObject]))
    {
      GSTLSCredentials   *cred;

      cred = [credentialsCache objectForKey: key];
      if (now - cred->when > 300.0)
        {
          [credentialsCache removeObjectForKey: key];
        }
    }
  [credentialsLock unlock];
}

+ (void) initialize
{
  if (nil == credentialsLock)
    {
      credentialsLock = [NSLock new];
      credentialsCache = [NSMutableDictionary new];

      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(housekeeping:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (GSTLSCredentials*) selfSigned: (BOOL)debug
{
  NSString	*crtPath = standardizedPath(@"self-signed-crt");
  NSString	*keyPath = standardizedPath(@"self-signed-key");
  NSData	*crt = [self dataForTLSFile: crtPath];
  NSData	*key = [self dataForTLSFile: keyPath];

  if (nil == crt || nil == key)
    {
      ENTER_POOL
      static NSString *tmp = @"organization = SelfSigned\n"
	@"state = Example\n"
	@"country = EX\n"
	@"cn = SelfSigned\n"
	@"serial = 007\n"
	@"expiration_days = 730\n"
	@"dns_name = server.selfsigned.com\n"
	@"tls_www_server\n"
	@"encryption_key\n";
      NSFileManager	*mgr = [NSFileManager defaultManager];
      NSString		*path = NSTemporaryDirectory();
      NSFileHandle      *devNull = [NSFileHandle fileHandleWithNullDevice];
      NSTask		*task;
      NSString		*tmpCrt;
      NSString		*tmpKey;
      NSString		*tmpTmp;

      path = [path stringByAppendingPathComponent: [[NSUUID UUID] UUIDString]];
      tmpCrt = [path stringByAppendingPathExtension: @"crt"];
      tmpKey = [path stringByAppendingPathExtension: @"key"];
      tmpTmp = [path stringByAppendingPathExtension: @"tmp"];
      [tmp writeToFile: tmpTmp atomically: NO];

      task = [NSTask new];
      [task setLaunchPath: @"certtool"];
      [task setArguments: [NSArray arrayWithObjects:
	@"--generate-privkey", @"--sec-param", @"high", @"--outfile", tmpKey,
	nil]];
      [task setStandardOutput: devNull];
      [task setStandardError: devNull];
      [task launch];
      [task waitUntilExit];
      RELEASE(task);
      key = [NSData dataWithContentsOfFile: tmpKey];

      task = [NSTask new];
      [task setLaunchPath: @"certtool"];
      [task setArguments: [NSArray arrayWithObjects:
	@"--generate-self-signed", @"--load-privkey", tmpKey,
	@"--template", tmpTmp, @"--outfile", tmpCrt,
	nil]];
      [task setStandardOutput: devNull];
      [task setStandardError: devNull];
      [task launch];
      [task waitUntilExit];
      RELEASE(task);
      crt = [NSData dataWithContentsOfFile: tmpCrt];

      [mgr removeFileAtPath: tmpCrt handler: nil];
      [mgr removeFileAtPath: tmpKey handler: nil];
      [mgr removeFileAtPath: tmpTmp handler: nil];

      if (key && crt)
        {
          [self setData: crt forTLSFile: crtPath];
          [self setData: key forTLSFile: keyPath];
        }

      LEAVE_POOL
      if (nil == key)
	{
	  NSLog(@"Failed to make self-signed certificate key using 'certtool'");
	  return nil;
	}
      if (nil == crt)
	{
	  NSLog(@"Failed to make self-signed certificate using 'certtool'");
          return nil;
        }
    }

  return [self credentialsFromCAFile: nil
		       defaultCAFile: nil
			  revokeFile: nil
		   defaultRevokeFile: nil
		     certificateFile: crtPath
		  certificateKeyFile: keyPath
	      certificateKeyPassword: nil
			    asClient: NO
			       debug: debug];
}

+ (GSTLSCredentials*) credentialsFromCAFile: (NSString*)ca
                              defaultCAFile: (NSString*)dca
                                 revokeFile: (NSString*)rv
                          defaultRevokeFile: (NSString*)drv
                            certificateFile: (NSString*)cf
                         certificateKeyFile: (NSString*)ck
                     certificateKeyPassword: (NSString*)cp
                                   asClient: (BOOL)client
                                      debug: (BOOL)debug
{
  GSTLSCredentials      *c;
  NSMutableString       *k;

  /* Build a unique key for the credentials based on all the
   * information used to build them (apart from password used
   * to load the key).
   */
  k = [NSMutableString stringWithCapacity: 1024];
  ca = standardizedPath(ca);
  if (nil != ca) [k appendString: ca];
  [k appendString: @":"];
  if (nil != dca) [k appendString: dca];
  [k appendString: @":"];
  rv = standardizedPath(rv);
  if (nil != rv) [k appendString: rv];
  [k appendString: @":"];
  if (nil != drv) [k appendString: drv];
  [k appendString: @":"];
  if (nil != cf) [k appendString: cf];
  [k appendString: @":"];
  if (nil != ck) [k appendString: ck];

  [credentialsLock lock];
  c = [credentialsCache objectForKey: k];
  if (nil != c)
    {
      [c retain];
      if (debug)
        {
          NSLog(@"Re-used credentials %p for '%@'", c, k);
        }
    }
  [credentialsLock unlock];

  if (nil == c)
    {
      c = [self new];
      c->name = [k copy];
      c->when = [NSDate timeIntervalSinceReferenceDate];

      gnutls_certificate_allocate_credentials(&c->certcred);
      c->freeCred = YES;        // Need to free on dealloc

      /* Set the default trusted authority certificates.
       */
      if ([dca length] > 0)
        {
          const char    *path;
          int           ret;

          path = [dca gnutlsFileSystemRepresentation];
          ret = gnutls_certificate_set_x509_trust_file(c->certcred,
            path, GNUTLS_X509_FMT_PEM);
          if (ret < 0)
            {
              NSLog(@"Problem loading trusted authorities from %@: %s",
                dca, gnutls_strerror(ret));
            }
          else
            {
              if (ret > 0)
                {
                  c->trust = YES;   // Loaded at least one trusted CA
                }
              if (debug)
                {
                  NSLog(@"Default trusted authorities (from %@): %d",
                   dca, ret);
                }
            }
        }
      else
	{
          const char    *path;
          int           ret;

	  /* Try system sertificates, and if those fail, try base library ones.
	   */
	  ret = gnutls_certificate_set_x509_system_trust(c->certcred);
	  if (ret < 0)
	    {
	      NSBundle	*bundle = [NSBundle bundleForClass: [NSObject class]];
	      NSString	*str;

	      str = [bundle pathForResource: @"ca-certificates"
				     ofType: @"crt"
				inDirectory: @"GSTLS"];
	      str = standardizedPath(str);
	      path = [str gnutlsFileSystemRepresentation];
	      ret = gnutls_certificate_set_x509_trust_file(c->certcred,
		path, GNUTLS_X509_FMT_PEM);
	      if (ret >= 0)
		{
		  if (debug)
		    {
		      NSLog(@"Default trusted authorities (from base) %d", ret);
		    }
		  if (ret > 0)
		    {
		      c->trust = YES;   // Loaded at least one trusted CA
		    }
		}
	    }
	  else
	    {
              if (debug)
                {
                  NSLog(@"Default trusted authorities (from O/S) %d", ret);
                }
	      if (ret > 0)
		{
		  c->trust = YES;   // Loaded at least one trusted CA
		}
	    }
	}

      /* Load any specified trusted authority certificates.
       */
      if ([ca length] > 0)
        {
          const char    *path;
          int           ret;

          path = [dca gnutlsFileSystemRepresentation];
          ret = gnutls_certificate_set_x509_trust_file(c->certcred,
            path, GNUTLS_X509_FMT_PEM);
          if (ret < 0)
            {
              NSLog(@"Problem loading trusted authorities from %@: %s",
                ca, gnutls_strerror(ret));
            }
          else
            {
              if (ret > 0)
                {
                  c->trust = YES;
                }
              else if (0 == ret)
                {
                  NSLog(@"No certificates processed from %@", ca);
                }
              if (debug)
                {
                  NSLog(@"Trusted authorities (from %@): %d", ca, ret);
                }
            }
        }

      /* Load default revocation list.
       */
      if ([drv length] > 0)
        {
          const char    *path;
          int           ret;

          path = [drv gnutlsFileSystemRepresentation];
          ret = gnutls_certificate_set_x509_crl_file(c->certcred,
            path, GNUTLS_X509_FMT_PEM);
          if (ret < 0)
            {
              NSLog(@"Problem loading default revocation list from %@: %s",
                drv, gnutls_strerror(ret));
            }
          else
            {
              if (debug)
                {
                  NSLog(@"Default revocations (from %@): %d", drv, ret);
                }
            }
        }

      /* Load any specified revocation list.
       */
      if ([rv length] > 0)
        {
          const char    *path;
          int           ret;

          path = [rv gnutlsFileSystemRepresentation];
          ret = gnutls_certificate_set_x509_crl_file(c->certcred,
            path, GNUTLS_X509_FMT_PEM);
          if (ret < 0)
            {
              NSLog(@"Problem loading revocation list from %@: %s",
                rv, gnutls_strerror(ret));
            }
          else
            {
              if (0 == ret)
                {
                  NSLog(@"No revocations processed from %@", rv);
                }
              if (debug)
                {
                  NSLog(@"Revocations (from %@): %d", rv, ret);
                }
            }
        }

      /* Get the key for our certificate .. if one is specified.
       */
      if (nil != ck)
        {
          c->key = [[GSTLSPrivateKey keyFromFile: ck
                                    withPassword: cp] retain];
          if (nil == c->key)
            {
              [c release];
              return nil;
            }
        }

      /* Load our certificate (may be a list) if the file is specified.
       */
      if (nil != cf)
        {
          c->list = [[GSTLSCertificateList listFromFile: cf] retain];
          if (nil == c->list)
            {
              [c release];
              return nil;
            }
        }

      /* If we have loaded a certificate, we add it to the credentials
       * using the certificate key so we can use it.
       */
      if (nil != c->list)
        {
          int   ret;

          ret = gnutls_certificate_set_x509_key(c->certcred,
            [c->list certificateList], [c->list count], [c->key key]);
          if (ret < 0)
            {
              c->freeCred = NO; // Already freed
              NSLog(@"Unable to set certificate for session: %s",
                gnutls_strerror(ret));
              [c release];
              return nil;
            }
/*
          if (NO == client)
            {
                // FIXME ... if the server certificate required DH params ...
              c->dhParams = [[GSTLSDHParams current] retain];
              gnutls_certificate_set_dh_params(c->certcred,
                [c->dhParams params]);
            }
*/
        }

      if (debug)
        {
          NSLog(@"%@ created credentials %p for '%@'", self, c, k);
        }
      [credentialsLock lock];
      [credentialsCache setObject: c forKey: c->name];
      [credentialsLock unlock];
    }

  return [c autorelease];
}


- (void) dealloc
{
  if (nil != name)
    {
      if (YES == freeCred)
        {
          gnutls_certificate_free_credentials(certcred);
        }
      DESTROY(key);
      DESTROY(list);
      DESTROY(dhParams);
      DESTROY(name);
    }
  [super dealloc];
}

- (gnutls_certificate_credentials_t) credentials
{
  return certcred;
}

- (GSTLSPrivateKey*) key
{
  return key;
}

- (GSTLSCertificateList*) list
{
  return list;
}

- (BOOL) trust
{
  return trust;
}
@end


#if GNUTLS_VERSION_NUMBER >= 0x020C00
/* Callback used only when debug is enabled, to print the request for a
 * certificate and the response to that request.
 * NB. This function always returns the certificate set for the session
 * even if that certificate does not match the CAs or algorithms requested
 * by the server.  This differs from the default behavior which is for the
 * library code to only return a certificate matching the request.
 * So, the logging of a returned certificate does not guarantee that the
 * certificate is acceptable to the server.
 */
static int
retrieve_callback(gnutls_session_t session,
  const gnutls_datum_t *req_ca_rdn,
  int nreqs,
  const gnutls_pk_algorithm_t *sign_algos,
  int sign_algos_length,
  gnutls_retr2_st *st)
{
  GSTLSSession  *s = gnutls_session_get_ptr(session);
  char          issuer_dn[256];
  int           i;
  int           ret;
  size_t        len;

  /* Print the server's trusted CAs
   */
  if (nreqs > 0)
    NSLog(@"- Server's trusted authorities:");
  else
    NSLog(@"- Server did not send us any trusted authorities names.");

  /* print the names (if any) */
  for (i = 0; i < nreqs; i++)
    {
      len = sizeof(issuer_dn);
      ret = gnutls_x509_rdn_get(&req_ca_rdn[i], issuer_dn, &len);
      if (ret >= 0)
        {
          NSLog(@"   [%d]: %s", i, issuer_dn);
        }
    }

  /* Select a certificate and return it.
   * The certificate must be of any of the "sign algorithms"
   * supported by the server.
   */
  if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509)
    {
      GSTLSCredentials          *credentials = [s credentials];
      GSTLSPrivateKey           *key = [credentials key];
      GSTLSCertificateList      *list = [credentials list];
      int                       count = (int)[list count];
      gnutls_x509_crt_t         *crts = [list certificateList];
      NSMutableString           *m;

      m = [NSMutableString stringWithCapacity: 2000];
      for (i = 0; i < count; i++)
        {
          [GSTLSCertificateList certInfo: crts[i] to: m];
        }
      if (0 == count)
        {
          [m appendString: @"None."];
        }
      NSLog(@"Certificates retrieved for sending to peer -\n%@", m);

      st->cert_type = GNUTLS_CRT_X509;
      st->ncerts = count;
      st->cert.x509 = crts;
      st->key.x509 = [key key];
      return 0;
    }
  else
    {
      NSLog(@"Certificates retrieved for sending to peer -\n"
	@"None: not a request for an X509 certificate.");
      return -1;
    }
}
#endif

@implementation GSTLSSession

+ (GSTLSSession*) sessionWithOptions: (NSDictionary*)options
                           direction: (BOOL)isOutgoing
                           transport: (void*)ioHandle
                                push: (GSTLSIOW)pushFunc
                                pull: (GSTLSIOR)pullFunc
{
  GSTLSSession  *sess;

  sess = [[self alloc] initWithOptions: options
                             direction: isOutgoing
                             transport: ioHandle
                                  push: pushFunc
                                  pull: pullFunc];
  return [sess autorelease];
}

- (BOOL) active
{
  return active;
}

- (NSTimeInterval) age
{
  return [NSDate timeIntervalSinceReferenceDate] - created;
}

- (GSTLSCredentials*) credentials
{
  return credentials;
}

- (void) dealloc
{
  [self finalize];
  DESTROY(opts);
  DESTROY(credentials);
  DESTROY(problem);
  DESTROY(issuer);
  DESTROY(owner);
  [super dealloc];
}

- (BOOL) debug
{
  return debug;
}

- (BOOL) disconnect: (BOOL)reusable
{
  BOOL  ok = YES;

  if (YES == active || YES == handshake)
    {
      int	result;

      active = NO;
      handshake = NO;
      if (NO == reusable)
        {
	  /* Since the connection is not reusable, we need only try once.
	   */
          result = gnutls_bye(session, GNUTLS_SHUT_WR);
        }
      else
        {
	  NSTimeInterval	start;

	  /* Attempting to do a clean shutdown on a reusable connection,
	   * so we keep retrying for a little while to let the other end
	   * close down cleanly.
	   */
	  start = [NSDate timeIntervalSinceReferenceDate];
          do
            {
              result = gnutls_bye(session, GNUTLS_SHUT_RDWR);
            }
          while ((GNUTLS_E_AGAIN == result || GNUTLS_E_INTERRUPTED == result)
	    && ([NSDate timeIntervalSinceReferenceDate] - start) < 10.0);
        }
      if (result < 0)
	{
	  ok = NO;
	}
    }
  if (YES == setup)
    {
      setup = NO;
      gnutls_db_remove_session(session);
      gnutls_deinit(session);
    }
  return ok;
}

- (void) finalize
{
  [self disconnect: NO];
  [super finalize];
}

- (NSString*) hostName
{
  if (outgoing)
    {
      return [opts objectForKey: GSTLSServerName];
    }
  return nil;
}

- (id) initWithOptions: (NSDictionary*)options
             direction: (BOOL)isOutgoing
             transport: (void*)ioHandle
                  push: (GSTLSIOW)pushFunc
                  pull: (GSTLSIOR)pullFunc
{
  if (nil != (self = [super init]))
    {
      GSTLSCredentials	*cr;
      NSString  	*ca;
      NSString  	*dca;
      NSString  	*rv;
      NSString  	*drv;
      NSString  	*cf;
      NSString  	*ck;
      NSString  	*cp;
      NSString  	*pri;
      NSString  	*str;
      BOOL      	trust;
      BOOL      	verify;

      /* Set this early because it is needed in debug output during init.
       */
      handle = ioHandle;

      created = [NSDate timeIntervalSinceReferenceDate];
      opts = [options copy];
      outgoing = isOutgoing ? YES : NO;

      if (YES == outgoing)
        {
          verify = verifyServer;        // Verify connection to remote server
        }
      else
        {
          verify = verifyClient;        // Verify certificate of remote client
        }
      str = [opts objectForKey: GSTLSVerify];
      if (nil != str)
        {
          verify = [str boolValue];
        }

      debug = (globalDebug > 0) ? YES : NO;
      if (NO == debug)
        {
          debug = [[opts objectForKey: GSTLSDebug] boolValue];
        }

      /* Now initialise session and set it up.  It's simplest to always
       * allocate a credentials structure at this point (and get rid of
       * it when the session is disconnected) too.
       */
      if (YES == outgoing)
        {
          gnutls_init(&session, GNUTLS_CLIENT);

          str = [opts objectForKey: GSTLSServerName];
          if ([str length] > 0)
            {
              const char        *ptr = [str UTF8String];
              unsigned          len = strlen(ptr);
              int               ret;

              ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, ptr, len);
              if (debug)
                {
                  if (ret < 0)
                    {
                      NSLog(@"%p %@: failed '%s'",
                        handle, GSTLSServerName, gnutls_strerror(ret));
                    }
                  else
                    {
                      NSLog(@"%p %@: set to '%s'",
                        handle, GSTLSServerName, ptr);
                    }
                }
            }
          else if (debug)
            {
              NSLog(@"%p %@: not set", handle, GSTLSServerName);
            }
        }
      else
        {
          gnutls_init(&session, GNUTLS_SERVER);
          if (NO == verify)
            {
              /* We don't want to demand/verify the client certificate,
               * but we still ask the other end to send it so that higher
               * level code can see what distinguished names are in it.
               */
              gnutls_certificate_server_set_request(session,
                GNUTLS_CERT_REQUEST);
            }
          else
            {
              /* We request the client certificate and require them client
               * end to send it (if not, we don't allow the session).
               */
              gnutls_certificate_server_set_request(session,
                GNUTLS_CERT_REQUIRE);
            }
        }
      setup = YES;

      cf = [opts objectForKey: GSTLSCertificateFile];

      if (nil == cf && NO == outgoing)
	{
	  /* Server with no certiticate supplied: generate self signed one.
	   */
	  cr = [GSTLSCredentials selfSigned: debug];
	}
      else
	{
	  ca = [opts objectForKey: GSTLSCAFile];
	  dca = caFile;
	  rv = [opts objectForKey: GSTLSRevokeFile];
	  drv = revokeFile;
	  ck = [opts objectForKey: GSTLSCertificateKeyFile];
	  cp =  [opts objectForKey: GSTLSCertificateKeyPassword];

	  cr = [GSTLSCredentials credentialsFromCAFile: ca
					 defaultCAFile: dca
					    revokeFile: rv
				     defaultRevokeFile: drv
				       certificateFile: cf
				    certificateKeyFile: ck
				certificateKeyPassword: cp
					      asClient: outgoing
						 debug: debug];
	}

      if (cr)
        {
	  ASSIGN(credentials, cr);
	}
      else
	{
          RELEASE(self);
          return nil;
        }

      trust = [credentials trust];
      if (YES == verify && NO == trust)
        {
          NSLog(@"You have requested that a TLS/SSL connection be to a remote"
            @" system with a verified certificate, but have provided no trusted"
            @" certificate authorities.");
          NSLog(@"If you did not use the GSTLSCAFile option to specify a file"
            @" containing certificate authorities for a session, and did not"
            @" specify a default file using the GSTLSCAFile user default or"    
            @" the GS_TLS_CA_FILE environment variable, then the system will"
            @" have attempted to use the GSTLS/ca-certificates.crt file in the"
            @" gnustep-base resource bundle.  Unfortunately, it has not been"
            @" possible to read any trusted certificate authorities from"
            @" these locations.");
        }

      pri = [opts objectForKey: NSStreamSocketSecurityLevelKey];
      str = [opts objectForKey: GSTLSPriority];
      if (nil == pri && nil == str)
        {
          str = priority;       // Default setting
        }
      if (YES == [str isEqual: @"SSLv3"])
        {
          pri = NSStreamSocketSecurityLevelSSLv3;
          str = nil;
        }
      else if (YES == [str isEqual: @"TLSv1"])
        {
          pri = NSStreamSocketSecurityLevelTLSv1;
          str = nil;
        }

      if (nil == str)
        {
          if ([pri isEqual: NSStreamSocketSecurityLevelNone] == YES)
            {
              // pri = NSStreamSocketSecurityLevelNone;
              GSOnceMLog(@"NSStreamSocketSecurityLevelNone is insecure ..."
                @" not implemented");
              DESTROY(self);
              return nil;
            }
          else if ([pri isEqual: NSStreamSocketSecurityLevelSSLv2] == YES)
            {
              // pri = NSStreamSocketSecurityLevelSSLv2;
              GSOnceMLog(@"NSStreamSocketSecurityLevelSSLv2 is insecure ..."
                @" not implemented");
              DESTROY(self);
              return nil;
            }
          else if ([pri isEqual: NSStreamSocketSecurityLevelSSLv3] == YES)
            {
#if GNUTLS_VERSION_NUMBER < 0x020C00
              const int proto_prio[2] = {
                GNUTLS_SSL3,
                0 };
              gnutls_protocol_set_priority(session, proto_prio);
#else
              gnutls_priority_set_direct(session,
                "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0", NULL);
#endif
              GSOnceMLog(@"NSStreamSocketSecurityLevelSSLv3 is insecure ..."
                @" please change your code to stop using it");
            }
          else if ([pri isEqual: NSStreamSocketSecurityLevelTLSv1] == YES)
            {
#if GNUTLS_VERSION_NUMBER < 0x020C00
              const int proto_prio[4] = {
#if	defined(GNUTLS_TLS1_2)
                GNUTLS_TLS1_2,
#endif
                GNUTLS_TLS1_1,
                GNUTLS_TLS1_0,
                0 };
              gnutls_protocol_set_priority(session, proto_prio);
#else
              gnutls_priority_set_direct(session,
                "NORMAL:-VERS-SSL3.0:+VERS-TLS-ALL", NULL);
#endif
            }
          else
            {
#if GNUTLS_VERSION_NUMBER < 0x020C00
              gnutls_set_default_priority(session);
#else
              /* By default we disable SSL3.0 as the 'POODLE' attack (Oct 2014)
               * renders it insecure.
               */
              gnutls_priority_set_direct(session, "NORMAL:-VERS-SSL3.0", NULL);
#endif
            }
        }
      else
        {
#if GNUTLS_VERSION_NUMBER < 0x020C00
	  gnutls_set_default_priority(session);
#else
	  /* By default we disable SSL3.0 as the 'POODLE' attack (Oct 2014)
	   * renders it insecure.
	   */
          const char *err_pos;
          if (gnutls_priority_set_direct(session, [str UTF8String], &err_pos))
            {
              NSLog(@"Invalid GSTLSPriority: %s", err_pos);
              NSLog(@"Falling back to NORMAL:-VERS-SSL3.0");
              gnutls_priority_set_direct(session, "NORMAL:-VERS-SSL3.0", NULL);
            }
#endif
        }

      /* Set certificate credentials for this session.
       */
      gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
        [credentials credentials]);

#if GNUTLS_VERSION_NUMBER >= 0x020C00
      if (YES == outgoing && debug)
        {
          /* Set a callback to log handling of a request (from the server)
           * for the client certificate.  The callback always returns the
           * certificate set for this session, even if that does not match
           * the server's request.
           */
          gnutls_certificate_set_retrieve_function(
            [credentials credentials], retrieve_callback);
        }
#endif
      
      /* Set transport layer to use 
       */
#if GNUTLS_VERSION_NUMBER < 0x020C00
      gnutls_transport_set_lowat(session, 0);
#endif
      gnutls_transport_set_pull_function(session, pullFunc);
      gnutls_transport_set_push_function(session, pushFunc);
      gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)ioHandle);
      gnutls_session_set_ptr(session, (void*)self);
    }

  return self;
}

- (BOOL) handshake
{
  int   ret;

  if (YES == active || NO == setup)
    {
      return YES;       // Handshake completed or impossible.
    }

  handshake = YES;
  ret = gnutls_handshake(session);
  if (ret < 0)
    {
      if (gnutls_error_is_fatal(ret))
        {
          NSString      *p;

          p = [NSString stringWithFormat: @"%s", gnutls_strerror(ret)];

          /* We want to differentiate between errors which are usually
           * due to the remote end not expecting to be using TLS/SSL,
           * and errors which are caused by other interoperability
           * issues.  The first sort are not normally worth reporting.
           */
          if (ret == GNUTLS_E_UNEXPECTED_PACKET_LENGTH
            || ret == GNUTLS_E_FATAL_ALERT_RECEIVED
            || ret == GNUTLS_E_DECRYPTION_FAILED
#ifdef GNUTLS_E_PREMATURE_TERMINATION
            || ret == GNUTLS_E_PREMATURE_TERMINATION
#endif
            || ret == GNUTLS_E_UNSUPPORTED_VERSION_PACKET)
            {
	      NSString	*extra = nil;

	      switch (ret)
		{
		  case GNUTLS_E_FATAL_ALERT_RECEIVED:
		    extra = @"The TLS protocol does not tell us why the remote"
		      @" end sent an alert, but the most common problem during"
		      @" handshake is a cipher mismatch";
		      break;
		  case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
                  case GNUTLS_E_PREMATURE_TERMINATION:
		    extra = @"Most often this is due to the remote end not"
		      @" expecting/supporting TLS";
		    break;
		}
	      if (extra)
		{
		  p = [p stringByAppendingFormat: @"\n%@", extra];
		}
              ASSIGN(problem, p);
              if (debug)
                {
                  NSLog(@"%p in handshake: %@", handle, p);
                }
            }
          else
            {
              ASSIGN(problem, p);
              NSLog(@"%p in handshake: %@", handle, p);
            }
          [self disconnect: NO];
          return YES;   // Failed ... not active.
        }
      else
        {
          return NO;    // Non-fatal error needs a retry.
        }
    }
  else
    {
      NSString  *str;
      BOOL      requireVerified;

      active = YES;     // The TLS session is now active.
      handshake = NO;   // Handshake is over.

      if (YES == outgoing)
        {
          requireVerified = verifyServer;  // Verify remote server certificate?
        }
      else
        {
          requireVerified = verifyClient;  // Verify remote client certificate?
        }
      str = [opts objectForKey: GSTLSVerify];
      if (nil != str)
        {
          requireVerified = [str boolValue];
        }

      /* We always try verification (and can report failure).
       * The requireVerified flag controls whether a verification failure
       * results in disconnect.
       */
      if (globalDebug > 1)
        {
          NSLog(@"%p trying verify:\n%@", handle, [self sessionInfo]);
        }
      ret = [self verify];
      if (ret < 0)
        {
          if (globalDebug > 1
	    || (requireVerified && globalDebug > 0)
            || YES == [[opts objectForKey: GSTLSDebug] boolValue])
            {
              NSLog(@"%p unable to verify SSL connection - %s",
                handle, gnutls_strerror(ret));
              NSLog(@"%p failed verify:\n%@", handle, [self sessionInfo]);
            }
          if (requireVerified)
            {
              [self disconnect: NO];
            }
	  else if (outgoing && nil == [opts objectForKey: GSTLSVerify])
	    {
	      /* We notify about verification failure on outgoing connections
	       * if the failure was ignored, unless it was specifically turned
	       * off by the app (GSTLSVerify set to NO). That is to say, if
	       * strict verification was turned off by environment variable
	       * or user default.  This is intended to allow an application
	       * to catch connection attempts which would have failed if the
	       * default setting had been to use strict verification.
	       */
              [[NSNotificationCenter defaultCenter]
                postNotificationName: GSTLSVerifyFailedNotification
                  object: self];
	    }
        }
      else
        {
          if (globalDebug > 1)
            {
              NSLog(@"%p succeeded verify:\n%@", handle, [self sessionInfo]);
            }
        }
      return YES;       // Handshake complete
    }
}

- (NSString*) issuer
{
  return issuer;
}

- (NSDictionary*) options
{
  return opts;
}

- (NSString*) owner
{
  return owner;
}

- (size_t) pending
{
  return gnutls_record_check_pending(session);
}

- (NSString*) problem
{
  return problem;
}

- (NSInteger) read: (void*)buf length: (NSUInteger)len
{
  int   result = gnutls_record_recv(session, buf, len);

  if (result < 0)
    {
      NSString  *p;

      if (GNUTLS_E_AGAIN == result)
        {
          errno = EAGAIN;       // Need to retry.
        }
      else if (GNUTLS_E_INTERRUPTED == result)
        {
          errno = EINTR;        // Need to retry
        }
      else if (gnutls_error_is_fatal(result))
        {
          p = [NSString stringWithFormat: @"%s", gnutls_strerror(result)];
          ASSIGN(problem, p);
          if (debug)
            {
              NSLog(@"%p in tls read: %@", handle, p);
            }
          if (EAGAIN == errno || EINTR == errno)
            {
              errno = EBADF;    // Fatal ... don't retry
            }
        }
      else
        {
          if (GNUTLS_E_WARNING_ALERT_RECEIVED == result)
            {
              if (debug)
                {
                  p = [NSString stringWithFormat: @"%s",
                    gnutls_alert_get_name(gnutls_alert_get(session))];
                  NSLog(@"%p in tls read: %@", handle, p);
                }
            }
          errno = EAGAIN;       // Need to retry.
        }
      result = -1;
#if	defined(_WIN32)
      /* Windows specific code expects to use winsock functions for error
       * codes rather than looking at errno, so we must translate a few.
       */
      if (EAGAIN == errno)
	WSASetLastError(WSAEWOULDBLOCK);
      else if (EINTR == errno)
	WSASetLastError(WSAEINTR);
      else
	WSASetLastError(errno);
#endif
    }
  return result;
}

- (NSInteger) write: (const void*)buf length: (NSUInteger)len
{
  int   result = gnutls_record_send(session, buf, len);

  if (result < 0)
    {
      if (GNUTLS_E_AGAIN == result)
        {
          errno = EAGAIN;       // Need to retry.
        }
      else if (GNUTLS_E_INTERRUPTED == result)
        {
          errno = EINTR;        // Need to retry
        }
      else if (gnutls_error_is_fatal(result))
        {
          NSString      *p;

          p = [NSString stringWithFormat: @"%s", gnutls_strerror(result)];
          ASSIGN(problem, p);
          if (debug)
            {
              NSLog(@"%p in tls write: %@", handle, p);
            }
          if (EAGAIN == errno || EINTR == errno)
            {
              errno = EBADF;    // Fatal ... don't retry
            }
        }
      else
        {
          errno = EAGAIN;       // Need to retry.
        }
      result = -1;
#if	defined(_WIN32)
      /* Windows specific code expects to use winsock functions for error
       * codes rather than looking at errno, so we must translate a few.
       */
      if (EAGAIN == errno)
	WSASetLastError(WSAEWOULDBLOCK);
      else if (EINTR == errno)
	WSASetLastError(WSAEINTR);
      else
	WSASetLastError(errno);
#endif
    }
  return result;
}

/* Copied/based on the public domain code provided by gnutls
 * to print the session ... I've left in details for features
 * we don't yet support.
 */
- (NSString*) sessionInfo
{
  NSMutableString               *str;
  const char                    *tmp;
  gnutls_credentials_type_t     cred;
  gnutls_kx_algorithm_t         kx;
  int                           dhe = 0;
#if     defined(XXX_ECDH)
  /* At some point we may want to implement ecdh */
  int                           ecdh = 0;
#endif

  str = [NSMutableString stringWithCapacity: 2000];

  if (outgoing)
    {
      [str appendFormat: @"- Outgoing session: %p to '%@'\n",
	self, [self hostName]];
    }
  else
    {
      [str appendFormat: @"- Oncoming session: %p\n", self];
    }

  /* get the key exchange's algorithm name
   */
  kx = gnutls_kx_get(session);
  tmp = gnutls_kx_get_name(kx);
  [str appendFormat: _(@"- Key Exchange: %s\n"), tmp];

  /* Check the authentication type used and switch to the appropriate.
   */
  cred = gnutls_auth_get_type(session);
  switch (cred)
    {
      case GNUTLS_CRD_IA:
        [str appendString: _(@"- TLS/IA session\n")];
        break;

      case GNUTLS_CRD_SRP:
#ifdef ENABLE_SRP
        [str appendFormat: _(@"- SRP session with username %s\n"),
          gnutls_srp_server_get_username(session)];
#endif
        break;

      case GNUTLS_CRD_PSK:
#if 0
        /* This returns NULL in server side.
         */
        if (gnutls_psk_client_get_hint(session) != NULL)
          {
            [str appendFormat: _(@"- PSK authentication. PSK hint '%s'\n"),
              gnutls_psk_client_get_hint(session)];
          }
        /* This returns NULL in client side.
         */
        if (gnutls_psk_server_get_username(session) != NULL)
          {
            [str appendFormat: _(@"- PSK authentication. Connected as '%s'\n"),
              gnutls_psk_server_get_username(session)];
          }

        if (GNUTLS_KX_ECDHE_PSK == kx)
          {
            ecdh = 1;
          }
        else if (GNUTLS_KX_DHE_PSK == kx)
          {
            dhe = 1;
          }
#endif
        break;

      case GNUTLS_CRD_ANON:      /* anonymous authentication */
#if 0
        [str appendFormat: _(@"- Anonymous authentication.\n")];
        if (GNUTLS_KX_ANON_ECDH == kx)
          {
            ecdh = 1;
          }
        else if (GNUTLS_KX_ANON_DH == kx)
          {
            dhe = 1;
          }
#endif
        break;

      case GNUTLS_CRD_CERTIFICATE:       /* certificate authentication */
      /* Check if we have been using ephemeral Diffie-Hellman.
       */
      if (GNUTLS_KX_DHE_RSA == kx || GNUTLS_KX_DHE_DSS == kx)
        {
          dhe = 1;
        }
#if defined(XXX_ECDH)
      if (GNUTLS_KX_ECDHE_RSA == kx || GNUTLS_KX_ECDHE_ECDSA == kx)
        {
          dhe = 0;
          ecdh = 1;
        }
#endif
        tmp = gnutls_certificate_type_get_name(
          gnutls_certificate_type_get(session));
        [str appendFormat: _(@"- Authentication using certificate type: %s\n"),
          tmp];

        break;
    }                           /* switch */

#if     defined(XXXECDH)
  if (ecdh != 0)
    {
      [str appendFormat: _(@"- Ephemeral ECDH using curve %s\n"),
        gnutls_ecc_curve_get_name(gnutls_ecc_curve_get(session))];
    }
#endif
  if (dhe != 0)
    {
      [str appendFormat: _(@"- Ephemeral DH using prime of %d bits\n"),
        gnutls_dh_get_prime_bits(session)];
    }

  /* print the protocol's name (eg TLS 1.0) 
   */
  tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
  [str appendFormat: _(@"- Protocol: %s\n"), tmp];

  /* print the certificates of the peer.
   */
  if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509)
    {
      unsigned int            cert_list_size = 0;
      const gnutls_datum_t    *cert_list;

      cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
      [str appendString: @"- "];
      if (0 == cert_list_size)
        {
          [str appendString: _(@"Peer provided no certificate.")];
          [str appendString: @"\n"];
        }
      else
        {
          int cert_num;
      
          if (cert_list_size > 1)
            {
              [str appendString: _(@"Peer certificates")];
            }
          else
            {
              [str appendString: _(@"Peer certificate")];
            }
          [str appendString: @"\n"];
          for (cert_num = 0; cert_num < cert_list_size; cert_num++)
            {
              gnutls_x509_crt_t cert;

              gnutls_x509_crt_init(&cert);
              /* NB. the list of peer certificate is in memory in native
               * format (DER) rather than the normal file format (PEM).
               */
              gnutls_x509_crt_import(cert,
                &cert_list[cert_num], GNUTLS_X509_FMT_DER);

              [str appendFormat: _(@"- Index %d of %d, "),
		cert_num, cert_list_size];

              [GSTLSCertificateList certInfo: cert to: str];

              gnutls_x509_crt_deinit(cert);
            }
        }
    }
  else
    {
      tmp = gnutls_certificate_type_get_name(
        gnutls_certificate_type_get(session));
      [str appendFormat: _(@"- Certificate Type: %s\n"), tmp];
    }

  /* print the name of the cipher used.
   * eg 3DES.
   */
  tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
  [str appendFormat: _(@"- Cipher: %s\n"), tmp];

  /* Print the MAC algorithms name.
   * eg SHA1
   */
  tmp = gnutls_mac_get_name(gnutls_mac_get(session));
  [str appendFormat: _(@"- MAC: %s\n"), tmp];

  return str;
}

- (int) verify
{
  NSArray               *names;
  NSString              *nameList;
  NSString              *str;
  NSMutableString       *ci;
  unsigned int          status;
  const gnutls_datum_t  *cert_list;
  unsigned int          cert_list_size;
  int                   ret;
  gnutls_x509_crt_t     cert;

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers2(session, &status);
  if (ret < 0)
    {
      str = [NSString stringWithFormat:
        @"TLS verification: error %s", gnutls_strerror(ret)];
      ASSIGN(problem, str);
      if (debug) NSLog(@"%p %@", handle, problem);
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  str = @"";
  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    str = [str stringByAppendingString:
      @", certificate hasn't got a known issuer"];

  if (status & GNUTLS_CERT_REVOKED)
    str = [str stringByAppendingString:
      @", certificate has been revoked"];

#if     defined(GNUTLS_CERT_EXPIRED)
  if (status & GNUTLS_CERT_EXPIRED)
    str = [str stringByAppendingString:
      @", certificate has expired"];
#endif

#if     defined(GNUTLS_CERT_NOT_ACTIVATED)
  if (status & GNUTLS_CERT_NOT_ACTIVATED)
    str = [str stringByAppendingString:
      @", certificate is not yet activated"];
#endif

  if (status & GNUTLS_CERT_INVALID)
    {
      if ([str length])
	{
          str = [NSString stringWithFormat:
	    @"TLS verification: remote certificate is not trusted%@.", str];
	}
      else
	{
	  str = @"TLS verification: remote certificate is not trusted.";
	}
      ASSIGN(problem, str);
      if (debug) NSLog(@"%p %@", handle, problem);
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  /* Up to here the process is the same for X.509 certificates and
   * OpenPGP keys. From now on X.509 certificates are assumed. This can
   * be easily extended to work with openpgp keys as well.
   */
  if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
    {
      ASSIGN(problem,
        @"TLS verification: remote certificate not of the X509 type.");
      if (debug) NSLog(@"%p %@", handle, problem);
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  if (gnutls_x509_crt_init(&cert) < 0)
    {
      ASSIGN(problem, @"TLS verification: error in certificate initialization");
      gnutls_x509_crt_deinit(cert);
      if (debug) NSLog(@"%p %@", handle, problem);
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
  if (cert_list == NULL)
    {
      ASSIGN(problem, @"TLS verification: no certificate from remote end!");
      gnutls_x509_crt_deinit(cert);
      if (debug) NSLog(@"%p %@", handle, problem);
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
    {
      ASSIGN(problem, @"TLS verification: error parsing certificate");
      gnutls_x509_crt_deinit(cert);
      if (debug) NSLog(@"%p %@", handle, problem);
      return GNUTLS_E_CERTIFICATE_ERROR;
    }
  else
    {
#if GNUTLS_VERSION_NUMBER >= 0x030507
      gnutls_datum_t    dn;

      if (GNUTLS_E_SUCCESS == gnutls_x509_crt_get_dn3(cert, &dn, 0))
        {
          ASSIGN(owner, [NSString stringWithUTF8String: (const char*)dn.data]);
          gnutls_free(dn.data);
        }
      if (GNUTLS_E_SUCCESS == gnutls_x509_crt_get_issuer_dn3(cert, &dn, 0))
        {
          ASSIGN(issuer, [NSString stringWithUTF8String: (const char*)dn.data]);
          gnutls_free(dn.data);
        }
#else
      char              dn[1024];
      size_t            dn_size;

      /* Get certificate owner and issuer
       */
      dn_size = sizeof(dn)-1;
      gnutls_x509_crt_get_dn(cert, dn, &dn_size);
      dn[dn_size] = '\0';
      ASSIGN(owner, [NSString stringWithUTF8String: dn]);
      
      dn_size = sizeof(dn)-1;
      gnutls_x509_crt_get_issuer_dn(cert, dn, &dn_size);
      dn[dn_size] = '\0';
      ASSIGN(issuer, [NSString stringWithUTF8String: dn]);
#endif
    }

  ci = [NSMutableString stringWithCapacity: 2000];
  [GSTLSCertificateList certInfo: cert to: ci];

  nameList = [opts objectForKey: GSTLSRemoteHosts];
  if (nil == nameList)
    {
      /* If nothing is specified, assume the connection host name
       * (if any) should be used for verification.
       */
      nameList = [opts objectForKey: GSTLSServerName];
      if ([nameList length] > 0)
        {
          names = [NSArray arrayWithObject: nameList];
        }
      else
        {
          names = nil;
        }
    }
  else
    {
      /* The string is a comma separated list of permitted host names.
       * If explicitly set to be empty, no host verification is done.
       */
      names = [nameList componentsSeparatedByString: @","];
      if ([names count] == 0)
        {
          names = nil;
        }
    }

  if (nil != names)
    {
      NSEnumerator      *enumerator = [names objectEnumerator];
      BOOL              found = NO;
      NSString          *name;

      while (nil != (name = [enumerator nextObject]))
        {
          if (gnutls_x509_crt_check_hostname(cert, [name UTF8String]))
            {
              found = YES;
              break;
            }
        }
      if (NO == found)
        {
          str = [NSString stringWithFormat:
            @"TLS verification: hostname does not match '%@' in %@",
            nameList, ci];
          ASSIGN(problem, str);
          gnutls_x509_crt_deinit(cert);
          if (debug) NSLog(@"%p %@", handle, problem);
          return GNUTLS_E_CERTIFICATE_ERROR;
        }
    }

  names = [opts objectForKey: GSTLSIssuers];
  if ([names isKindOfClass: [NSArray class]])
    {
      if (nil == issuer || NO == [names containsObject: issuer])
        {
          str = [NSString stringWithFormat:
            @"TLS verification: issuer does not match '%@' in %@",
            names, ci];
          ASSIGN(problem, str);
	  gnutls_x509_crt_deinit(cert);
          if (debug) NSLog(@"%p %@", handle, problem);
          return GNUTLS_E_CERTIFICATE_ERROR;
        }
    }

  names = [opts objectForKey: GSTLSOwners];
  if ([names isKindOfClass: [NSArray class]])
    {
      if (nil == owner || NO == [names containsObject: owner])
        {
          str = [NSString stringWithFormat:
            @"TLS verification: owner does not match '%@' in %@",
            names, ci];
          ASSIGN(problem, str);
	  gnutls_x509_crt_deinit(cert);
          if (debug) NSLog(@"%p %@", handle, problem);
          return GNUTLS_E_CERTIFICATE_ERROR;
        }
    }

  gnutls_x509_crt_deinit(cert);
  return 0;     // Verified
}

@end

#else   /* HAVE_SCHANNEL */

/* Native Windows TLS support using SChannel (SSPI) for the protocol,
 * CryptoAPI for certificate handling and CNG for private keys.
 */
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS     // Needed for SCH_CREDENTIALS
#include <subauth.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <wchar.h>

/* Certificate policy flags (from wininet.h).
 */
#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#endif
#ifndef SECURITY_FLAG_IGNORE_WRONG_USAGE
#define SECURITY_FLAG_IGNORE_WRONG_USAGE        0x00000200
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#endif

#define GS_ISC_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT \
  | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM \
  | ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_MANUAL_CRED_VALIDATION \
  | ISC_REQ_EXTENDED_ERROR)
#define GS_ASC_FLAGS (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT \
  | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM \
  | ASC_REQ_EXTENDED_ERROR | ASC_REQ_MUTUAL_AUTH)
#define GS_ENCODING     (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define GS_READ_CHUNK   32768

typedef struct {
  CredHandle                    cred;
  CtxtHandle                    ctxt;
  BOOL                          haveCred;
  BOOL                          haveCtxt;
  BOOL                          hsDone;         // SChannel completed handshake
  BOOL                          needInput;      // Partial handshake message
  BOOL                          renegotiate;    // Handshake restarted by peer
  BOOL                          peerClosed;     // close_notify or EOF seen
  BOOL                          failed;         // Fatal record layer error
  BOOL                          quiet;          // Failure not worth logging
  SecPkgContext_StreamSizes     sizes;
  WCHAR                         *target;        // Server name (SNI)
  NSMutableData                 *inBuf;         // Encrypted data from peer
  NSMutableData                 *outBuf;        // Encrypted data for peer
  NSUInteger                    outOff;
  NSMutableData                 *decBuf;        // Decrypted data from peer
  NSUInteger                    decOff;
  NSUInteger                    pendingPlain;   // Plaintext queued in outBuf
} GSSChannelState;

static NSLock           *keyLock = nil;
static NSMutableSet     *keyNames = nil;
static LONG             keyCounter = 0;

static WCHAR *
newWide(NSString *s)
{
  NSUInteger    l = [s length];
  WCHAR         *w = malloc((l + 1) * sizeof(WCHAR));

  [s getCharacters: (unichar*)w range: NSMakeRange(0, l)];
  w[l] = 0;
  return w;
}

static NSString *
fromWide(const WCHAR *w)
{
  if (NULL == w)
    {
      return nil;
    }
  return [NSString stringWithCharacters: (const unichar*)w length: wcslen(w)];
}

static NSString *
secStatusString(DWORD s)
{
  WCHAR buf[512];
  DWORD len;

  len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM
    | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, s, 0,
    buf, sizeof(buf)/sizeof(*buf), NULL);
  while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'
    || buf[len-1] == ' ' || buf[len-1] == '.'))
    {
      len--;
    }
  if (len > 0)
    {
      return [NSString stringWithFormat: @"%@ (0x%08lx)",
        [NSString stringWithCharacters: (unichar*)buf length: len],
        (unsigned long)s];
    }
  return [NSString stringWithFormat: @"SChannel error 0x%08lx",
    (unsigned long)s];
}

/* Windows specific code expects to use winsock functions for error
 * codes rather than looking at errno, so we set both.
 */
static void
setTLSErrno(int e)
{
  errno = e;
  if (EAGAIN == e)
    WSASetLastError(WSAEWOULDBLOCK);
  else if (EINTR == e)
    WSASetLastError(WSAEINTR);
  else
    WSASetLastError(e);
}

static BOOL
transportWouldBlock(void)
{
  int   e = WSAGetLastError();

  if (EAGAIN == errno || EINTR == errno || EWOULDBLOCK == errno
    || WSAEWOULDBLOCK == e || WSAEINTR == e)
    {
      return YES;
    }
  return NO;
}

static NSDate *
dateFromFileTime(FILETIME ft)
{
  ULARGE_INTEGER        u;

  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return [NSDate dateWithTimeIntervalSince1970:
    (NSTimeInterval)u.QuadPart / 10000000.0 - 11644473600.0];
}

static NSString *
attributeName(LPCSTR oid)
{
  static const struct { const char *oid; NSString *name; } map[] = {
    { "2.5.4.3", @"CN" },
    { "2.5.4.4", @"surName" },
    { "2.5.4.5", @"serialNumber" },
    { "2.5.4.6", @"C" },
    { "2.5.4.7", @"L" },
    { "2.5.4.8", @"ST" },
    { "2.5.4.9", @"STREET" },
    { "2.5.4.10", @"O" },
    { "2.5.4.11", @"OU" },
    { "2.5.4.12", @"title" },
    { "2.5.4.42", @"givenName" },
    { "0.9.2342.19200300.100.1.1", @"UID" },
    { "0.9.2342.19200300.100.1.25", @"DC" },
    { "1.2.840.113549.1.9.1", @"EMAIL" },
  };
  unsigned      i;

  for (i = 0; i < sizeof(map)/sizeof(*map); i++)
    {
      if (0 == strcmp(oid, map[i].oid))
        {
          return map[i].name;
        }
    }
  return [NSString stringWithUTF8String: oid];
}

static NSString *
escapedDNValue(NSString *v)
{
  NSMutableString       *m;
  NSUInteger            len = [v length];
  NSUInteger            i;

  m = [NSMutableString stringWithCapacity: len + 8];
  for (i = 0; i < len; i++)
    {
      unichar   c = [v characterAtIndex: i];

      if (c == ',' || c == '+' || c == '"' || c == '\\' || c == '<'
        || c == '>' || c == ';' || (0 == i && (c == '#' || c == ' '))
        || (len - 1 == i && c == ' '))
        {
          [m appendString: @"\\"];
        }
      [m appendFormat: @"%C", c];
    }
  return m;
}

/* Returns the distinguished name in RFC4514 string form.
 */
static NSString *
dnString(CERT_NAME_BLOB *blob)
{
  CERT_NAME_INFO        *info = NULL;
  DWORD                 size = 0;
  NSMutableString       *s;
  DWORD                 i;

  if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_NAME,
    blob->pbData, blob->cbData, CRYPT_DECODE_ALLOC_FLAG, NULL,
    &info, &size))
    {
      return nil;
    }
  s = [NSMutableString stringWithCapacity: 256];
  for (i = info->cRDN; i-- > 0;)
    {
      CERT_RDN  *rdn = &info->rgRDN[i];
      DWORD     j;

      if ([s length] > 0)
        {
          [s appendString: @","];
        }
      for (j = 0; j < rdn->cRDNAttr; j++)
        {
          CERT_RDN_ATTR *a = &rdn->rgRDNAttr[j];
          DWORD         n;
          WCHAR         *w;

          if (j > 0)
            {
              [s appendString: @"+"];
            }
          [s appendString: attributeName(a->pszObjId)];
          [s appendString: @"="];
          n = CertRDNValueToStrW(a->dwValueType, &a->Value, NULL, 0);
          w = malloc((n + 1) * sizeof(WCHAR));
          CertRDNValueToStrW(a->dwValueType, &a->Value, w, n);
          w[n] = 0;
          [s appendString: escapedDNValue(fromWide(w))];
          free(w);
        }
    }
  LocalFree(info);
  return s;
}

static void
certInfo(PCCERT_CONTEXT cert, NSMutableString *str)
{
  CRYPT_INTEGER_BLOB    *serial = &cert->pCertInfo->SerialNumber;
  NSMutableString       *hex = [NSMutableString stringWithCapacity: 64];
  BYTE                  sha1[20];
  DWORD                 len = sizeof(sha1);
  DWORD                 i;

  [str appendString: @"X.509 Certificate Information:\n"];
  [str appendFormat: @"\tSubject: %@\n",
    dnString(&cert->pCertInfo->Subject)];
  [str appendFormat: @"\tIssuer: %@\n",
    dnString(&cert->pCertInfo->Issuer)];
  for (i = serial->cbData; i-- > 0;)
    {
      [hex appendFormat: @"%02x", serial->pbData[i]];
    }
  [str appendFormat: @"\tSerial Number (hex): %@\n", hex];
  [str appendFormat: @"\tValidity:\n\t\tNot Before: %@\n\t\tNot After: %@\n",
    dateFromFileTime(cert->pCertInfo->NotBefore),
    dateFromFileTime(cert->pCertInfo->NotAfter)];
  if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID,
    sha1, &len))
    {
      [hex setString: @""];
      for (i = 0; i < len; i++)
        {
          [hex appendFormat: @"%02x", sha1[i]];
        }
      [str appendFormat: @"\tSHA-1 fingerprint: %@\n", hex];
    }
}

/* Splits PEM data into an array of (label, DER data) pairs.  Data which
 * is not PEM is treated as a single DER block with an empty label.
 * Blocks using legacy (OpenSSL) PEM encryption have a third element
 * containing the DEK-Info header value.
 */
static NSArray *
pemBlocks(NSData *data)
{
  NSMutableArray        *result = [NSMutableArray array];
  NSString              *s;
  NSRange               r;

  s = AUTORELEASE([[NSString alloc] initWithData: data
                                        encoding: NSISOLatin1StringEncoding]);
  r = [s rangeOfString: @"-----BEGIN "];
  if (0 == r.length)
    {
      if ([data length] > 0)
        {
          [result addObject: [NSArray arrayWithObjects: @"", data, nil]];
        }
      return result;
    }
  while (r.length > 0)
    {
      NSUInteger        start = NSMaxRange(r);
      NSUInteger        length = [s length];
      NSString          *label;
      NSString          *body;
      NSString          *dek = nil;
      NSRange           e;
      NSData            *der;

      e = [s rangeOfString: @"-----" options: 0
                     range: NSMakeRange(start, length - start)];
      if (0 == e.length)
        {
          break;
        }
      label = [s substringWithRange: NSMakeRange(start, e.location - start)];
      start = NSMaxRange(e);
      e = [s rangeOfString: [NSString stringWithFormat: @"-----END %@-----",
        label] options: 0 range: NSMakeRange(start, length - start)];
      if (0 == e.length)
        {
          break;
        }
      body = [s substringWithRange: NSMakeRange(start, e.location - start)];
      if ([body rangeOfString: @"Proc-Type:"].length > 0)
        {
          NSRange       h = [body rangeOfString: @"DEK-Info:"];
          NSRange       blank;

          /* Headers are separated from the base64 data by a blank line.
           */
          body = [body stringByReplacingOccurrencesOfString: @"\r"
                                                 withString: @""];
          blank = [body rangeOfString: @"\n\n"];
          if (h.length > 0 && blank.length > 0)
            {
              h = [body lineRangeForRange: [body rangeOfString: @"DEK-Info:"]];
              dek = [[body substringWithRange: h] substringFromIndex: 9];
              dek = [dek stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceAndNewlineCharacterSet]];
              body = [body substringFromIndex: NSMaxRange(blank)];
            }
          else
            {
              body = nil;
            }
        }
      der = (nil == body) ? nil : AUTORELEASE([[NSData alloc]
        initWithBase64EncodedString: body
        options: NSDataBase64DecodingIgnoreUnknownCharacters]);
      if (nil != der)
        {
          [result addObject: [NSArray arrayWithObjects: label, der, dek, nil]];
        }
      start = NSMaxRange(e);
      r = [s rangeOfString: @"-----BEGIN " options: 0
                     range: NSMakeRange(start, length - start)];
    }
  return result;
}

/* Adds the certificates found in data to the store, returning the number
 * added.  If 'first' is not NULL it is set to the first certificate added.
 */
static int
addCertificates(HCERTSTORE store, NSData *data, NSString *path,
  PCCERT_CONTEXT *first)
{
  NSEnumerator  *e = [pemBlocks(data) objectEnumerator];
  NSArray       *b;
  int           count = 0;

  while (nil != (b = [e nextObject]))
    {
      NSString          *label = [b objectAtIndex: 0];
      NSData            *der = [b objectAtIndex: 1];
      PCCERT_CONTEXT    ctx = NULL;

      if ([label length] > 0 && NO == [label isEqual: @"CERTIFICATE"]
        && NO == [label isEqual: @"X509 CERTIFICATE"])
        {
          continue;
        }
      if (CertAddEncodedCertificateToStore(store, GS_ENCODING,
        [der bytes], (DWORD)[der length], CERT_STORE_ADD_USE_EXISTING,
        (NULL != first && NULL == *first) ? &ctx : NULL))
        {
          count++;
          if (NULL != ctx)
            {
              *first = ctx;
            }
        }
      else if ([label length] > 0)
        {
          NSLog(@"Unable to parse certificate in '%@': %@",
            path, secStatusString(GetLastError()));
        }
    }
  return count;
}

static int
addCRLs(HCERTSTORE store, NSData *data, NSString *path)
{
  NSEnumerator  *e = [pemBlocks(data) objectEnumerator];
  NSArray       *b;
  int           count = 0;

  while (nil != (b = [e nextObject]))
    {
      NSString  *label = [b objectAtIndex: 0];
      NSData    *der = [b objectAtIndex: 1];

      if ([label length] > 0 && NO == [label isEqual: @"X509 CRL"])
        {
          continue;
        }
      if (CertAddEncodedCRLToStore(store, GS_ENCODING, [der bytes],
        (DWORD)[der length], CERT_STORE_ADD_USE_EXISTING, NULL))
        {
          count++;
        }
      else
        {
          NSLog(@"Unable to parse revocation list in '%@': %@",
            path, secStatusString(GetLastError()));
        }
    }
  return count;
}

/* Wraps a PKCS#1 RSA or SEC1 EC private key in a PKCS#8 structure.
 */
static NSData *
wrapPrivateKey(NSData *der, BOOL isEC)
{
  static BYTE                   nullParams[] = { 0x05, 0x00 };
  CRYPT_PRIVATE_KEY_INFO        info;
  CRYPT_ECC_PRIVATE_KEY_INFO    *ecc = NULL;
  BYTE                          *params = NULL;
  BYTE                          *out = NULL;
  DWORD                         len = 0;
  NSData                        *result = nil;

  memset(&info, 0, sizeof(info));
  info.PrivateKey.cbData = (DWORD)[der length];
  info.PrivateKey.pbData = (BYTE*)[der bytes];
  if (isEC)
    {
      LPSTR     oid;

      if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ECC_PRIVATE_KEY,
        [der bytes], (DWORD)[der length], CRYPT_DECODE_ALLOC_FLAG, NULL,
        &ecc, &len) || NULL == ecc->szCurveOid)
        {
          if (ecc) LocalFree(ecc);
          return nil;
        }
      oid = ecc->szCurveOid;
      if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
        &oid, CRYPT_ENCODE_ALLOC_FLAG, NULL, &params, &len))
        {
          LocalFree(ecc);
          return nil;
        }
      info.Algorithm.pszObjId = (LPSTR)szOID_ECC_PUBLIC_KEY;
      info.Algorithm.Parameters.cbData = len;
      info.Algorithm.Parameters.pbData = params;
    }
  else
    {
      info.Algorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
      info.Algorithm.Parameters.cbData = sizeof(nullParams);
      info.Algorithm.Parameters.pbData = nullParams;
    }
  if (CryptEncodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
    &info, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &len))
    {
      result = [NSData dataWithBytes: out length: len];
      SecureZeroMemory(out, len);
      LocalFree(out);
    }
  if (params) LocalFree(params);
  if (ecc) LocalFree(ecc);
  return result;
}

/* Derives a key as done by OpenSSL EVP_BytesToKey() with MD5 and a single
 * iteration (used by legacy PEM encryption).
 */
static NSData *
legacyPEMKey(NSData *password, NSData *salt, ULONG keyLen)
{
  BCRYPT_ALG_HANDLE     alg = NULL;
  NSMutableData         *key = [NSMutableData dataWithCapacity: 64];
  UCHAR                 digest[16];

  if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg,
    BCRYPT_MD5_ALGORITHM, NULL, 0)))
    {
      return nil;
    }
  while ([key length] < keyLen)
    {
      BCRYPT_HASH_HANDLE        h = NULL;
      NTSTATUS                  s;

      s = BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0);
      if (BCRYPT_SUCCESS(s) && [key length] > 0)
        {
          s = BCryptHashData(h, digest, sizeof(digest), 0);
        }
      if (BCRYPT_SUCCESS(s))
        {
          s = BCryptHashData(h, (PUCHAR)[password bytes],
            (ULONG)[password length], 0);
        }
      if (BCRYPT_SUCCESS(s))
        {
          s = BCryptHashData(h, (PUCHAR)[salt bytes], 8, 0);
        }
      if (BCRYPT_SUCCESS(s))
        {
          s = BCryptFinishHash(h, digest, sizeof(digest), 0);
        }
      if (h) BCryptDestroyHash(h);
      if (!BCRYPT_SUCCESS(s))
        {
          BCryptCloseAlgorithmProvider(alg, 0);
          return nil;
        }
      [key appendBytes: digest length: sizeof(digest)];
    }
  BCryptCloseAlgorithmProvider(alg, 0);
  SecureZeroMemory(digest, sizeof(digest));
  [key setLength: keyLen];
  return key;
}

/* Decrypts a key using legacy (OpenSSL) PEM encryption.
 */
static NSData *
decryptLegacyPEM(NSData *enc, NSString *dek, NSString *password,
  NSString *path)
{
  NSArray               *parts = [dek componentsSeparatedByString: @","];
  NSString              *cipher;
  NSString              *hex;
  LPCWSTR               algName;
  ULONG                 keyLen;
  ULONG                 blockLen;
  NSMutableData         *iv;
  NSData                *key;
  NSMutableData         *out;
  BCRYPT_ALG_HANDLE     alg = NULL;
  BCRYPT_KEY_HANDLE     k = NULL;
  ULONG                 outLen = 0;
  NTSTATUS              s;
  NSUInteger            i;

  if ([parts count] != 2)
    {
      NSLog(@"Bad DEK-Info header in '%@'", path);
      return nil;
    }
  cipher = [[parts objectAtIndex: 0] uppercaseString];
  hex = [parts objectAtIndex: 1];
  if ([cipher isEqual: @"DES-EDE3-CBC"])
    {
      algName = BCRYPT_3DES_ALGORITHM; keyLen = 24; blockLen = 8;
    }
  else if ([cipher isEqual: @"AES-128-CBC"])
    {
      algName = BCRYPT_AES_ALGORITHM; keyLen = 16; blockLen = 16;
    }
  else if ([cipher isEqual: @"AES-192-CBC"])
    {
      algName = BCRYPT_AES_ALGORITHM; keyLen = 24; blockLen = 16;
    }
  else if ([cipher isEqual: @"AES-256-CBC"])
    {
      algName = BCRYPT_AES_ALGORITHM; keyLen = 32; blockLen = 16;
    }
  else
    {
      NSLog(@"Unsupported private key encryption '%@' in '%@'",
        cipher, path);
      return nil;
    }
  if ([hex length] != blockLen * 2)
    {
      NSLog(@"Bad DEK-Info header in '%@'", path);
      return nil;
    }
  iv = [NSMutableData dataWithLength: blockLen];
  for (i = 0; i < blockLen; i++)
    {
      unsigned  v = 0;

      sscanf([[hex substringWithRange: NSMakeRange(i * 2, 2)] UTF8String],
        "%2x", &v);
      ((uint8_t*)[iv mutableBytes])[i] = (uint8_t)v;
    }
  key = legacyPEMKey([(nil == password ? @"" : password)
    dataUsingEncoding: NSUTF8StringEncoding], iv, keyLen);
  if (nil == key)
    {
      return nil;
    }

  out = [NSMutableData dataWithLength: [enc length]];
  s = BCryptOpenAlgorithmProvider(&alg, algName, NULL, 0);
  if (BCRYPT_SUCCESS(s))
    {
      s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    }
  if (BCRYPT_SUCCESS(s))
    {
      s = BCryptGenerateSymmetricKey(alg, &k, NULL, 0,
        (PUCHAR)[key bytes], keyLen, 0);
    }
  if (BCRYPT_SUCCESS(s))
    {
      s = BCryptDecrypt(k, (PUCHAR)[enc bytes], (ULONG)[enc length], NULL,
        [iv mutableBytes], blockLen, [out mutableBytes], (ULONG)[out length],
        &outLen, BCRYPT_BLOCK_PADDING);
    }
  if (k) BCryptDestroyKey(k);
  if (alg) BCryptCloseAlgorithmProvider(alg, 0);
  if (!BCRYPT_SUCCESS(s))
    {
      NSLog(@"Unable to decrypt private key in '%@' (bad password?)", path);
      return nil;
    }
  [out setLength: outLen];
  return out;
}

/* Returns the private key from a key file as PKCS#8 DER data.
 */
static NSData *
pkcs8FromKeyData(NSData *data, NSString *path, NSString *password,
  BOOL *encrypted)
{
  NSEnumerator  *e = [pemBlocks(data) objectEnumerator];
  NSArray       *b;

  while (nil != (b = [e nextObject]))
    {
      NSString  *label = [b objectAtIndex: 0];
      NSData    *der = [b objectAtIndex: 1];
      BOOL      isEC = [label isEqual: @"EC PRIVATE KEY"];

      if ([label isEqual: @"PRIVATE KEY"] || 0 == [label length])
        {
          *encrypted = NO;
          return der;
        }
      if ([label isEqual: @"ENCRYPTED PRIVATE KEY"])
        {
          *encrypted = YES;
          return der;
        }
      if (isEC || [label isEqual: @"RSA PRIVATE KEY"])
        {
          NSData        *pkcs8;

          if ([b count] > 2)
            {
              der = decryptLegacyPEM(der, [b objectAtIndex: 2],
                password, path);
              if (nil == der)
                {
                  return nil;
                }
            }
          *encrypted = NO;
          pkcs8 = wrapPrivateKey(der, isEC);
          if (nil == pkcs8)
            {
              NSLog(@"Unable to parse private key in '%@': %@",
                path, secStatusString(GetLastError()));
            }
          return pkcs8;
        }
    }
  NSLog(@"No private key found in '%@'", path);
  return nil;
}

static void
deleteKeyNamed(NSString *keyName)
{
  NCRYPT_PROV_HANDLE    prov = 0;
  NCRYPT_KEY_HANDLE     key = 0;
  WCHAR                 *w = newWide(keyName);

  if (ERROR_SUCCESS == NCryptOpenStorageProvider(&prov,
    MS_KEY_STORAGE_PROVIDER, 0))
    {
      if (ERROR_SUCCESS == NCryptOpenKey(prov, &key, w, 0, 0))
        {
          NCryptDeleteKey(key, 0);
        }
      NCryptFreeObject(prov);
    }
  free(w);
}

static NSString *
newKeyName(void)
{
  NSString      *keyName;

  keyName = [NSString stringWithFormat: @"GNUstep-GSTLS-%lu-%ld",
    (unsigned long)GetCurrentProcessId(),
    (long)InterlockedIncrement(&keyCounter)];
  [keyLock lock];
  [keyNames addObject: keyName];
  [keyLock unlock];
  return keyName;
}

static void
forgetKeyNamed(NSString *keyName)
{
  deleteKeyNamed(keyName);
  [keyLock lock];
  [keyNames removeObject: keyName];
  [keyLock unlock];
}

static void
GSTLSDeleteImportedKeys(void)
{
  NSEnumerator  *e;
  NSString      *k;

  [keyLock lock];
  e = [[keyNames allObjects] objectEnumerator];
  while (nil != (k = [e nextObject]))
    {
      deleteKeyNamed(k);
    }
  [keyNames removeAllObjects];
  [keyLock unlock];
}

/* Associates a persisted CNG key with a certificate so SChannel (which
 * performs private key operations in the LSA process and therefore can
 * not use ephemeral keys) is able to use it.
 */
static BOOL
setKeyForCertificate(PCCERT_CONTEXT cert, NSString *keyName)
{
  CRYPT_KEY_PROV_INFO   kpi;
  WCHAR                 *w = newWide(keyName);
  BOOL                  ok;

  memset(&kpi, 0, sizeof(kpi));
  kpi.pwszContainerName = w;
  kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
  ok = CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
    0, &kpi) ? YES : NO;
  free(w);
  return ok;
}

/* Imports a PKCS#8 key into the CNG key store and returns its name.
 */
static NSString *
importKey(NSData *pkcs8, BOOL encrypted, NSString *password, NSString *path)
{
  NCRYPT_PROV_HANDLE    prov = 0;
  NCRYPT_KEY_HANDLE     key = 0;
  NCryptBuffer          bufs[2];
  NCryptBufferDesc      desc;
  NSString              *keyName = newKeyName();
  WCHAR                 *wname = newWide(keyName);
  WCHAR                 *wpass = NULL;
  SECURITY_STATUS       s;

  s = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
  if (ERROR_SUCCESS == s)
    {
      bufs[0].cbBuffer = (ULONG)((wcslen(wname) + 1) * sizeof(WCHAR));
      bufs[0].BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
      bufs[0].pvBuffer = wname;
      desc.ulVersion = NCRYPTBUFFER_VERSION;
      desc.cBuffers = 1;
      desc.pBuffers = bufs;
      if (encrypted)
        {
          wpass = newWide(nil == password ? @"" : password);
          bufs[1].cbBuffer = (ULONG)((wcslen(wpass) + 1) * sizeof(WCHAR));
          bufs[1].BufferType = NCRYPTBUFFER_PKCS_SECRET;
          bufs[1].pvBuffer = wpass;
          desc.cBuffers = 2;
        }
      s = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &desc,
        &key, (PBYTE)[pkcs8 bytes], (DWORD)[pkcs8 length],
        NCRYPT_DO_NOT_FINALIZE_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);
      if (ERROR_SUCCESS == s)
        {
          s = NCryptFinalizeKey(key, 0);
          NCryptFreeObject(key);
        }
      NCryptFreeObject(prov);
    }
  free(wname);
  if (wpass)
    {
      SecureZeroMemory(wpass, wcslen(wpass) * sizeof(WCHAR));
      free(wpass);
    }
  if (ERROR_SUCCESS != s)
    {
      NSLog(@"Unable to import private key from '%@': %@",
        path, secStatusString((DWORD)s));
      forgetKeyNamed(keyName);
      return nil;
    }
  return keyName;
}

static BOOL
chainHasAnchor(PCCERT_CHAIN_CONTEXT chain, HCERTSTORE store)
{
  PCERT_SIMPLE_CHAIN    sc = chain->rgpChain[0];
  DWORD                 i;

  for (i = 0; i < sc->cElement; i++)
    {
      PCCERT_CONTEXT    f;

      f = CertFindCertificateInStore(store, GS_ENCODING, 0,
        CERT_FIND_EXISTING, sc->rgpElement[i]->pCertContext, NULL);
      if (NULL != f)
        {
          CertFreeCertificateContext(f);
          return YES;
        }
    }
  return NO;
}

static BOOL
chainIsRevoked(PCCERT_CHAIN_CONTEXT chain, HCERTSTORE crls)
{
  PCERT_SIMPLE_CHAIN    sc = chain->rgpChain[0];
  DWORD                 i;

  for (i = 0; i < sc->cElement; i++)
    {
      PCCERT_CONTEXT    c = sc->rgpElement[i]->pCertContext;
      PCCRL_CONTEXT     crl = NULL;

      while (NULL != (crl = CertEnumCRLsInStore(crls, crl)))
        {
          PCRL_ENTRY    entry = NULL;

          if (CertCompareCertificateName(X509_ASN_ENCODING,
            &c->pCertInfo->Issuer, &crl->pCrlInfo->Issuer)
            && CertFindCertificateInCRL(c, crl, 0, NULL, &entry)
            && NULL != entry)
            {
              CertFreeCRLContext(crl);
              return YES;
            }
        }
    }
  return NO;
}

static DWORD
chainPolicyError(PCCERT_CHAIN_CONTEXT chain, DWORD authType,
  DWORD checks, WCHAR *serverName)
{
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA      ssl;
  CERT_CHAIN_POLICY_PARA                para;
  CERT_CHAIN_POLICY_STATUS              status;

  memset(&ssl, 0, sizeof(ssl));
  ssl.cbSize = sizeof(ssl);
  ssl.dwAuthType = authType;
  ssl.fdwChecks = checks;
  ssl.pwszServerName = serverName;
  memset(&para, 0, sizeof(para));
  para.cbSize = sizeof(para);
  para.pvExtraPolicyPara = &ssl;
  memset(&status, 0, sizeof(status));
  status.cbSize = sizeof(status);
  if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
    &para, &status))
    {
      return GetLastError();
    }
  return status.dwError;
}

static SECURITY_STATUS
acquireCredentials(CredHandle *cred, BOOL outgoing, DWORD protocols,
  PCCERT_CONTEXT cert)
{
  PCCERT_CONTEXT        certs[1];
  TimeStamp             expiry;
  SECURITY_STATUS       s;
  DWORD                 flags;
  ULONG                 use;

  certs[0] = cert;
  use = outgoing ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND;
  if (outgoing)
    {
      /* We verify the server certificate ourselves after the handshake.
       */
      flags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    }
  else
    {
      flags = SCH_CRED_NO_SYSTEM_MAPPER;
    }

#if     defined(SCH_CREDENTIALS_VERSION)
  {
    SCH_CREDENTIALS     sc;
    TLS_PARAMETERS      tp;

    /* The newer structure is needed for TLS 1.3 support (Windows 10 1809
     * and later).  On older systems this fails and we fall back.
     */
    memset(&sc, 0, sizeof(sc));
    memset(&tp, 0, sizeof(tp));
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = flags;
    if (NULL != cert)
      {
        sc.cCreds = 1;
        sc.paCred = certs;
      }
    if (0 != protocols)
      {
        tp.grbitDisabledProtocols = ~protocols;
        sc.cTlsParameters = 1;
        sc.pTlsParameters = &tp;
      }
    s = AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, use, NULL,
      &sc, NULL, NULL, cred, &expiry);
    if (SEC_E_OK == s)
      {
        return s;
      }
  }
#endif

  {
    SCHANNEL_CRED       sc;

    memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.dwFlags = flags;
    if (NULL != cert)
      {
        sc.cCreds = 1;
        sc.paCred = certs;
      }
    if (0 == protocols)
      {
        protocols = outgoing
          ? (SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT
            | SP_PROT_TLS1_2_CLIENT)
          : (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER
            | SP_PROT_TLS1_2_SERVER);
      }
    sc.grbitEnabledProtocols = protocols;
    s = AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, use, NULL,
      &sc, NULL, NULL, cred, &expiry);
  }
  return s;
}

static NSString *
protocolName(DWORD p)
{
#if     defined(SP_PROT_TLS1_3)
  if (p & SP_PROT_TLS1_3) return @"TLS1.3";
#endif
  if (p & SP_PROT_TLS1_2) return @"TLS1.2";
  if (p & SP_PROT_TLS1_1) return @"TLS1.1";
  if (p & SP_PROT_TLS1_0) return @"TLS1.0";
  if (p & SP_PROT_SSL3) return @"SSL3.0";
  return [NSString stringWithFormat: @"Unknown (0x%lx)", (unsigned long)p];
}


@interface      GSTLSCredentials (SChannel)
- (PCCERT_CONTEXT) _certificate;
- (HCERTSTORE) _caStore;
- (HCERTSTORE) _crlStore;
- (BOOL) _exclusive;
@end

@implementation GSTLSCredentials

static GSTLSCredentials *selfSignedCredentials = nil;

/* Method to purge older credentials from cache.
 */
+ (void) housekeeping: (NSNotification*)n
{
  NSEnumerator          *enumerator;
  NSString              *key;
  NSTimeInterval        now;

  now = [NSDate timeIntervalSinceReferenceDate];
  [credentialsLock lock];
  enumerator = [[credentialsCache allKeys] objectEnumerator];
  while (nil != (key = [enumerator nextObject]))
    {
      GSTLSCredentials   *cred;

      cred = [credentialsCache objectForKey: key];
      if (now - cred->when > 300.0)
        {
          [credentialsCache removeObjectForKey: key];
        }
    }
  [credentialsLock unlock];
}

+ (void) initialize
{
  if (nil == credentialsLock)
    {
      credentialsLock = [NSLock new];
      credentialsCache = [NSMutableDictionary new];
      keyLock = [NSLock new];
      keyNames = [NSMutableSet new];

      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(housekeeping:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (GSTLSCredentials*) selfSigned: (BOOL)debug
{
  GSTLSCredentials      *c;
  NCRYPT_PROV_HANDLE    prov = 0;
  NCRYPT_KEY_HANDLE     key = 0;
  CERT_NAME_BLOB        subject;
  CRYPT_KEY_PROV_INFO   kpi;
  CRYPT_ALGORITHM_IDENTIFIER    alg;
  SYSTEMTIME            end;
  FILETIME              ft;
  ULARGE_INTEGER        u;
  PCCERT_CONTEXT        cert = NULL;
  const WCHAR           *dn = L"CN=SelfSigned, O=SelfSigned, C=EX";
  BYTE                  name[256];
  DWORD                 bits = 2048;
  NSString              *keyName;
  WCHAR                 *wname;
  SECURITY_STATUS       s;

  [credentialsLock lock];
  c = RETAIN(selfSignedCredentials);
  [credentialsLock unlock];
  if (nil != c)
    {
      return AUTORELEASE(c);
    }

  keyName = newKeyName();
  wname = newWide(keyName);
  s = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
  if (ERROR_SUCCESS == s)
    {
      s = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM,
        wname, 0, NCRYPT_OVERWRITE_KEY_FLAG);
      if (ERROR_SUCCESS == s)
        {
          s = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&bits, sizeof(bits), 0);
        }
      if (ERROR_SUCCESS == s)
        {
          s = NCryptFinalizeKey(key, 0);
        }
    }
  if (ERROR_SUCCESS == s)
    {
      subject.cbData = sizeof(name);
      subject.pbData = name;
      if (!CertStrToNameW(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, NULL,
        name, &subject.cbData, NULL))
        {
          s = (SECURITY_STATUS)GetLastError();
        }
    }
  if (ERROR_SUCCESS == s)
    {
      memset(&kpi, 0, sizeof(kpi));
      kpi.pwszContainerName = wname;
      kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
      memset(&alg, 0, sizeof(alg));
      alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
      GetSystemTimeAsFileTime(&ft);
      u.LowPart = ft.dwLowDateTime;
      u.HighPart = ft.dwHighDateTime;
      u.QuadPart += 730ULL * 24 * 3600 * 10000000;
      ft.dwLowDateTime = u.LowPart;
      ft.dwHighDateTime = u.HighPart;
      FileTimeToSystemTime(&ft, &end);
      cert = CertCreateSelfSignCertificate((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)key,
        &subject, 0, &kpi, &alg, NULL, &end, NULL);
      if (NULL == cert)
        {
          s = (SECURITY_STATUS)GetLastError();
        }
    }
  if (key) NCryptFreeObject(key);
  if (prov) NCryptFreeObject(prov);
  free(wname);

  if (NULL == cert)
    {
      NSLog(@"Failed to make self-signed certificate: %@",
        secStatusString((DWORD)s));
      forgetKeyNamed(keyName);
      return nil;
    }

  c = [self new];
  c->name = @"self-signed";
  c->when = [NSDate timeIntervalSinceReferenceDate];
  c->keyName = [keyName copy];
  c->cert = (void*)cert;
  c->trust = YES;
  if (debug)
    {
      NSLog(@"%@ created self-signed credentials %p", self, c);
    }

  [credentialsLock lock];
  if (nil == selfSignedCredentials)
    {
      ASSIGN(selfSignedCredentials, c);
    }
  else
    {
      RELEASE(c);
      c = RETAIN(selfSignedCredentials);
    }
  [credentialsLock unlock];
  return AUTORELEASE(c);
}

+ (GSTLSCredentials*) credentialsFromCAFile: (NSString*)ca
                              defaultCAFile: (NSString*)dca
                                 revokeFile: (NSString*)rv
                          defaultRevokeFile: (NSString*)drv
                            certificateFile: (NSString*)cf
                         certificateKeyFile: (NSString*)ck
                     certificateKeyPassword: (NSString*)cp
                                   asClient: (BOOL)client
                                      debug: (BOOL)debug
{
  GSTLSCredentials      *c;
  NSMutableString       *k;

  /* Build a unique key for the credentials based on all the
   * information used to build them (apart from password used
   * to load the key).
   */
  k = [NSMutableString stringWithCapacity: 1024];
  ca = standardizedPath(ca);
  if (nil != ca) [k appendString: ca];
  [k appendString: @":"];
  if (nil != dca) [k appendString: dca];
  [k appendString: @":"];
  rv = standardizedPath(rv);
  if (nil != rv) [k appendString: rv];
  [k appendString: @":"];
  if (nil != drv) [k appendString: drv];
  [k appendString: @":"];
  if (nil != cf) [k appendString: cf];
  [k appendString: @":"];
  if (nil != ck) [k appendString: ck];

  [credentialsLock lock];
  c = [credentialsCache objectForKey: k];
  if (nil != c)
    {
      [c retain];
      if (debug)
        {
          NSLog(@"Re-used credentials %p for '%@'", c, k);
        }
    }
  [credentialsLock unlock];

  if (nil == c)
    {
      HCERTSTORE        store = NULL;
      NSData            *data;
      int               n;

      c = [self new];
      c->name = [k copy];
      c->when = [NSDate timeIntervalSinceReferenceDate];

      if ([dca length] > 0 || [ca length] > 0)
        {
          store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
            CERT_STORE_CREATE_NEW_FLAG, NULL);
          c->caStore = (void*)store;
        }

      /* A default CA file replaces the operating system trust store.
       */
      if ([dca length] > 0)
        {
          c->exclusive = YES;
          data = [self dataForTLSFile: dca];
          if (nil == data)
            {
              NSLog(@"Problem loading trusted authorities from %@", dca);
            }
          else
            {
              n = addCertificates(store, data, dca, NULL);
              if (n > 0)
                {
                  c->trust = YES;
                }
              if (debug)
                {
                  NSLog(@"Default trusted authorities (from %@): %d", dca, n);
                }
            }
        }
      else
        {
          c->trust = YES;
          if (debug)
            {
              NSLog(@"Default trusted authorities (from O/S)");
            }
        }

      /* Load any specified trusted authority certificates.
       */
      if ([ca length] > 0)
        {
          data = [self dataForTLSFile: ca];
          if (nil == data)
            {
              NSLog(@"Problem loading trusted authorities from %@", ca);
            }
          else
            {
              n = addCertificates(store, data, ca, NULL);
              if (n > 0)
                {
                  c->trust = YES;
                }
              else
                {
                  NSLog(@"No certificates processed from %@", ca);
                }
              if (debug)
                {
                  NSLog(@"Trusted authorities (from %@): %d", ca, n);
                }
            }
        }

      /* Load revocation lists.
       */
      if ([drv length] > 0 || [rv length] > 0)
        {
          NSString      *files[2];
          int           i;

          files[0] = drv;
          files[1] = rv;
          c->crlStore = (void*)CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
            CERT_STORE_CREATE_NEW_FLAG, NULL);
          for (i = 0; i < 2; i++)
            {
              if ([files[i] length] == 0)
                {
                  continue;
                }
              data = [self dataForTLSFile: files[i]];
              if (nil == data)
                {
                  NSLog(@"Problem loading revocation list from %@", files[i]);
                  continue;
                }
              n = addCRLs((HCERTSTORE)c->crlStore, data, files[i]);
              if (debug)
                {
                  NSLog(@"Revocations (from %@): %d", files[i], n);
                }
            }
        }

      /* Load our certificate (may be a list) and its private key if the
       * file is specified.  If no key file is given, we look for the key
       * in the certificate file.
       */
      if (nil != cf)
        {
          PCCERT_CONTEXT        first = NULL;
          NSString              *kf;
          NSString              *keyName;
          NSData                *pkcs8;
          BOOL                  encrypted = NO;

          cf = standardizedPath(cf);
          data = [self dataForTLSFile: cf];
          if (nil == data)
            {
              NSLog(@"Unable to read certificate file '%@'", cf);
              RELEASE(c);
              return nil;
            }
          store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
            CERT_STORE_CREATE_NEW_FLAG, NULL);
          addCertificates(store, data, cf, &first);
          /* The certificate contexts keep the store (and so the rest of
           * the chain) alive.
           */
          CertCloseStore(store, 0);
          if (NULL == first)
            {
              NSLog(@"Unable to parse certificate file '%@'", cf);
              RELEASE(c);
              return nil;
            }
          c->cert = (void*)first;

          kf = standardizedPath(nil == ck ? cf : ck);
          data = [self dataForTLSFile: kf];
          if (nil == data)
            {
              NSLog(@"Unable to read private key file '%@'", kf);
              RELEASE(c);
              return nil;
            }
          pkcs8 = pkcs8FromKeyData(data, kf, cp, &encrypted);
          if (nil == pkcs8)
            {
              RELEASE(c);
              return nil;
            }
          keyName = importKey(pkcs8, encrypted, cp, kf);
          if (nil == keyName)
            {
              RELEASE(c);
              return nil;
            }
          c->keyName = [keyName copy];
          if (NO == setKeyForCertificate(first, keyName))
            {
              NSLog(@"Unable to set certificate for session: %@",
                secStatusString(GetLastError()));
              RELEASE(c);
              return nil;
            }
        }

      if (debug)
        {
          NSLog(@"%@ created credentials %p for '%@'", self, c, k);
        }
      [credentialsLock lock];
      [credentialsCache setObject: c forKey: c->name];
      [credentialsLock unlock];
    }

  return AUTORELEASE(c);
}

- (void) dealloc
{
  if (NULL != cert)
    {
      CertFreeCertificateContext((PCCERT_CONTEXT)cert);
    }
  if (NULL != caStore)
    {
      CertCloseStore((HCERTSTORE)caStore, 0);
    }
  if (NULL != crlStore)
    {
      CertCloseStore((HCERTSTORE)crlStore, 0);
    }
  if (nil != keyName)
    {
      forgetKeyNamed(keyName);
    }
  DESTROY(keyName);
  DESTROY(name);
  [super dealloc];
}

- (BOOL) trust
{
  return trust;
}

- (PCCERT_CONTEXT) _certificate
{
  return (PCCERT_CONTEXT)cert;
}

- (HCERTSTORE) _caStore
{
  return (HCERTSTORE)caStore;
}

- (HCERTSTORE) _crlStore
{
  return (HCERTSTORE)crlStore;
}

- (BOOL) _exclusive
{
  return exclusive;
}
@end


@implementation GSTLSSession

+ (GSTLSSession*) sessionWithOptions: (NSDictionary*)options
                           direction: (BOOL)isOutgoing
                           transport: (void*)ioHandle
                                push: (GSTLSIOW)push
                                pull: (GSTLSIOR)pull
{
  GSTLSSession  *sess;

  sess = [[self alloc] initWithOptions: options
                             direction: isOutgoing
                             transport: ioHandle
                                  push: push
                                  pull: pull];
  return AUTORELEASE(sess);
}

- (BOOL) active
{
  return active;
}

- (NSTimeInterval) age
{
  return [NSDate timeIntervalSinceReferenceDate] - created;
}

- (GSTLSCredentials*) credentials
{
  return credentials;
}

- (void) _freeState
{
  GSSChannelState       *st = (GSSChannelState*)session;

  if (NULL != st)
    {
      session = NULL;
      if (st->haveCtxt)
        {
          DeleteSecurityContext(&st->ctxt);
        }
      if (st->haveCred)
        {
          FreeCredentialsHandle(&st->cred);
        }
      free(st->target);
      RELEASE(st->inBuf);
      RELEASE(st->outBuf);
      RELEASE(st->decBuf);
      free(st);
    }
}

- (void) dealloc
{
  [self finalize];
  [self _freeState];
  DESTROY(opts);
  DESTROY(credentials);
  DESTROY(problem);
  DESTROY(issuer);
  DESTROY(owner);
  [super dealloc];
}

- (BOOL) debug
{
  return debug;
}

/* Sends queued encrypted data.  Returns 1 when everything has been sent,
 * 0 if the transport would block, -1 on failure.
 */
- (int) _flush
{
  GSSChannelState       *st = (GSSChannelState*)session;

  while (st->outOff < [st->outBuf length])
    {
      const uint8_t     *ptr = (const uint8_t*)[st->outBuf bytes];
      ssize_t           r;

      setTLSErrno(0);
      r = (*pushFunc)(handle, ptr + st->outOff,
        [st->outBuf length] - st->outOff);
      if (r > 0)
        {
          st->outOff += r;
        }
      else if (0 == r || transportWouldBlock())
        {
          return 0;
        }
      else
        {
          ASSIGN(problem, @"TLS write to the remote system failed");
          return -1;
        }
    }
  [st->outBuf setLength: 0];
  st->outOff = 0;
  return 1;
}

/* Reads encrypted data from the transport.  Returns the number of bytes
 * read, 0 at end of file, -1 if the transport would block, -2 on failure.
 */
- (int) _fill
{
  GSSChannelState       *st = (GSSChannelState*)session;
  NSUInteger            old = [st->inBuf length];
  ssize_t               r;

  [st->inBuf setLength: old + GS_READ_CHUNK];
  setTLSErrno(0);
  r = (*pullFunc)(handle, (uint8_t*)[st->inBuf mutableBytes] + old,
    GS_READ_CHUNK);
  if (r > 0)
    {
      [st->inBuf setLength: old + r];
      return (int)r;
    }
  [st->inBuf setLength: old];
  if (0 == r)
    {
      return 0;
    }
  if (transportWouldBlock())
    {
      return -1;
    }
  ASSIGN(problem, @"TLS read from the remote system failed");
  return -2;
}

static void
queueToken(GSSChannelState *st, SecBuffer *b, int count)
{
  int   i;

  for (i = 0; i < count; i++)
    {
      if (NULL != b[i].pvBuffer)
        {
          if (SECBUFFER_TOKEN == b[i].BufferType && b[i].cbBuffer > 0)
            {
              [st->outBuf appendBytes: b[i].pvBuffer length: b[i].cbBuffer];
            }
          FreeContextBuffer(b[i].pvBuffer);
          b[i].pvBuffer = NULL;
        }
    }
}

/* Removes the consumed part of the input buffer, keeping any extra data
 * SChannel did not process.
 */
static void
keepExtra(GSSChannelState *st, SecBuffer *b)
{
  if (SECBUFFER_EXTRA == b->BufferType && b->cbBuffer > 0)
    {
      uint8_t   *ptr = [st->inBuf mutableBytes];
      NSUInteger len = [st->inBuf length];

      memmove(ptr, ptr + len - b->cbBuffer, b->cbBuffer);
      [st->inBuf setLength: b->cbBuffer];
    }
  else
    {
      [st->inBuf setLength: 0];
    }
}

/* Calls InitializeSecurityContext or AcceptSecurityContext with the
 * supplied input, queueing any output to be sent to the peer.
 */
- (SECURITY_STATUS) _negotiate: (SecBufferDesc*)inDesc
{
  GSSChannelState       *st = (GSSChannelState*)session;
  SecBuffer             outb[2];
  SecBufferDesc         outDesc;
  SECURITY_STATUS       s;
  ULONG                 attrs = 0;

  outb[0].BufferType = SECBUFFER_TOKEN;
  outb[0].cbBuffer = 0;
  outb[0].pvBuffer = NULL;
  outb[1].BufferType = SECBUFFER_ALERT;
  outb[1].cbBuffer = 0;
  outb[1].pvBuffer = NULL;
  outDesc.ulVersion = SECBUFFER_VERSION;
  outDesc.cBuffers = 2;
  outDesc.pBuffers = outb;

  if (outgoing)
    {
      s = InitializeSecurityContextW(&st->cred,
        st->haveCtxt ? &st->ctxt : NULL, st->target, GS_ISC_FLAGS, 0, 0,
        inDesc, 0, &st->ctxt, &outDesc, &attrs, NULL);
    }
  else
    {
      s = AcceptSecurityContext(&st->cred,
        st->haveCtxt ? &st->ctxt : NULL, inDesc, GS_ASC_FLAGS, 0,
        &st->ctxt, &outDesc, &attrs, NULL);
    }
  if (SEC_E_OK == s || SEC_I_CONTINUE_NEEDED == s)
    {
      st->haveCtxt = YES;
    }
  queueToken(st, outb, 2);
  return s;
}

/* Advances the handshake as far as possible without blocking.
 * Returns 1 when complete, 0 when waiting for I/O, -1 on failure.
 */
- (int) _handshakeStep
{
  GSSChannelState       *st = (GSSChannelState*)session;
  int                   incompleteCredentials = 0;

  for (;;)
    {
      SecBuffer         inb[2];
      SecBufferDesc     inDesc;
      SECURITY_STATUS   s;
      int               r;

      r = [self _flush];
      if (r <= 0)
        {
          return r;
        }
      if (YES == st->hsDone)
        {
          s = QueryContextAttributesW(&st->ctxt, SECPKG_ATTR_STREAM_SIZES,
            &st->sizes);
          if (SEC_E_OK != s)
            {
              ASSIGN(problem, secStatusString(s));
              return -1;
            }
          return 1;
        }

      if (NO == st->haveCtxt && YES == outgoing)
        {
          /* Start the handshake by sending the client hello.
           */
          s = [self _negotiate: NULL];
          if (SEC_I_CONTINUE_NEEDED != s)
            {
              ASSIGN(problem, secStatusString(s));
              return -1;
            }
          continue;
        }

      if (YES == st->needInput || 0 == [st->inBuf length])
        {
          r = [self _fill];
          if (-1 == r)
            {
              return 0;
            }
          if (0 == r)
            {
              ASSIGN(problem, @"The TLS connection was closed by the remote"
                @" system during the handshake.\nMost often this is due to"
                @" the remote end not expecting/supporting TLS");
              st->quiet = YES;
              return -1;
            }
          if (r < 0)
            {
              return -1;
            }
          st->needInput = NO;
        }

      inb[0].BufferType = SECBUFFER_TOKEN;
      inb[0].cbBuffer = (ULONG)[st->inBuf length];
      inb[0].pvBuffer = [st->inBuf mutableBytes];
      inb[1].BufferType = SECBUFFER_EMPTY;
      inb[1].cbBuffer = 0;
      inb[1].pvBuffer = NULL;
      inDesc.ulVersion = SECBUFFER_VERSION;
      inDesc.cBuffers = 2;
      inDesc.pBuffers = inb;

      s = [self _negotiate: &inDesc];
      if (SEC_E_INCOMPLETE_MESSAGE == s)
        {
          st->needInput = YES;
          continue;
        }
      if (SEC_I_INCOMPLETE_CREDENTIALS == s && 0 == incompleteCredentials++)
        {
          /* The server asked for a client certificate but we have none;
           * try again to proceed without one.
           */
          continue;
        }
      if (SEC_E_OK == s || SEC_I_CONTINUE_NEEDED == s)
        {
          keepExtra(st, &inb[1]);
          if (SEC_E_OK == s)
            {
              st->hsDone = YES;
            }
          continue;
        }

      /* Try to send any alert generated, then fail.
       */
      [self _flush];
      ASSIGN(problem, secStatusString(s));
      if (SEC_E_INVALID_TOKEN == s || SEC_E_ILLEGAL_MESSAGE == s)
        {
          ASSIGN(problem, [problem stringByAppendingString:
            @"\nMost often this is due to the remote end not"
            @" expecting/supporting TLS"]);
          st->quiet = YES;
        }
      return -1;
    }
}

/* Handles a post-handshake message (TLS 1.3 session ticket or key update)
 * or a renegotiation request reported by DecryptMessage.
 */
- (int) _postHandshake: (NSData*)token
{
  GSSChannelState       *st = (GSSChannelState*)session;
  SecBuffer             inb[2];
  SecBufferDesc         inDesc;
  SECURITY_STATUS       s;
  NSMutableData         *saved;

  /* The token is passed in place of the encrypted input, any encrypted
   * data following it is processed once the handshake message is dealt
   * with.
   */
  saved = st->inBuf;
  st->inBuf = [token mutableCopy];
  inb[0].BufferType = SECBUFFER_TOKEN;
  inb[0].cbBuffer = (ULONG)[st->inBuf length];
  inb[0].pvBuffer = [st->inBuf mutableBytes];
  inb[1].BufferType = SECBUFFER_EMPTY;
  inb[1].cbBuffer = 0;
  inb[1].pvBuffer = NULL;
  inDesc.ulVersion = SECBUFFER_VERSION;
  inDesc.cBuffers = 2;
  inDesc.pBuffers = inb;
  s = [self _negotiate: &inDesc];
  if (SEC_E_OK == s || SEC_I_CONTINUE_NEEDED == s)
    {
      keepExtra(st, &inb[1]);
      [st->inBuf appendData: saved];
    }
  RELEASE(saved);
  if (SEC_E_OK == s)
    {
      [self _flush];
      return 0;
    }
  if (SEC_I_CONTINUE_NEEDED == s)
    {
      st->renegotiate = YES;
      st->hsDone = NO;
      st->needInput = NO;
      return 0;
    }
  ASSIGN(problem, secStatusString(s));
  return -1;
}

/* Decrypts as many complete records as are buffered.
 * Returns 0 on success, -1 on a fatal error.
 */
- (int) _decrypt
{
  GSSChannelState       *st = (GSSChannelState*)session;

  while ([st->inBuf length] > 0 && NO == st->peerClosed
    && NO == st->renegotiate && NO == st->failed)
    {
      SecBuffer         b[4];
      SecBufferDesc     d;
      SECURITY_STATUS   s;
      SecBuffer         *data = NULL;
      SecBuffer         *extra = NULL;
      NSData            *token = nil;
      int               i;

      b[0].BufferType = SECBUFFER_DATA;
      b[0].cbBuffer = (ULONG)[st->inBuf length];
      b[0].pvBuffer = [st->inBuf mutableBytes];
      for (i = 1; i < 4; i++)
        {
          b[i].BufferType = SECBUFFER_EMPTY;
          b[i].cbBuffer = 0;
          b[i].pvBuffer = NULL;
        }
      d.ulVersion = SECBUFFER_VERSION;
      d.cBuffers = 4;
      d.pBuffers = b;

      s = DecryptMessage(&st->ctxt, &d, 0, NULL);
      if (SEC_E_INCOMPLETE_MESSAGE == s)
        {
          return 0;
        }
      if (SEC_E_OK != s && SEC_I_RENEGOTIATE != s
        && SEC_I_CONTEXT_EXPIRED != s)
        {
          ASSIGN(problem, secStatusString(s));
          st->failed = YES;
          return -1;
        }
      for (i = 1; i < 4; i++)
        {
          if (SECBUFFER_DATA == b[i].BufferType && NULL == data)
            {
              data = &b[i];
            }
          else if (SECBUFFER_EXTRA == b[i].BufferType && NULL == extra)
            {
              extra = &b[i];
            }
        }
      if (NULL != data && data->cbBuffer > 0)
        {
          if (SEC_I_RENEGOTIATE == s)
            {
              token = [NSData dataWithBytes: data->pvBuffer
                                     length: data->cbBuffer];
            }
          else
            {
              if (st->decOff == [st->decBuf length])
                {
                  [st->decBuf setLength: 0];
                  st->decOff = 0;
                }
              [st->decBuf appendBytes: data->pvBuffer length: data->cbBuffer];
            }
        }
      if (NULL != extra && extra->cbBuffer > 0)
        {
          memmove([st->inBuf mutableBytes], extra->pvBuffer, extra->cbBuffer);
          [st->inBuf setLength: extra->cbBuffer];
        }
      else
        {
          [st->inBuf setLength: 0];
        }

      if (SEC_I_CONTEXT_EXPIRED == s)
        {
          st->peerClosed = YES;
        }
      else if (SEC_I_RENEGOTIATE == s)
        {
          if ([self _postHandshake: (nil == token) ? [NSData data] : token] < 0)
            {
              st->failed = YES;
              return -1;
            }
        }
    }
  return 0;
}

- (BOOL) disconnect: (BOOL)reusable
{
  GSSChannelState       *st = (GSSChannelState*)session;
  BOOL                  ok = YES;

  if (YES == active || YES == handshake)
    {
      active = NO;
      handshake = NO;
      if (NULL != st && YES == st->haveCtxt)
        {
          DWORD                 type = SCHANNEL_SHUTDOWN;
          SecBuffer             b;
          SecBufferDesc         d;
          NSTimeInterval        start;
          int                   r;

          b.BufferType = SECBUFFER_TOKEN;
          b.cbBuffer = sizeof(type);
          b.pvBuffer = &type;
          d.ulVersion = SECBUFFER_VERSION;
          d.cBuffers = 1;
          d.pBuffers = &b;
          if (SEC_E_OK == ApplyControlToken(&st->ctxt, &d))
            {
              [self _negotiate: NULL];
            }

	  /* For a reusable connection we keep retrying for a little while
	   * to let the close notification be sent.
	   */
	  start = [NSDate timeIntervalSinceReferenceDate];
          do
            {
              r = [self _flush];
            }
          while (0 == r && YES == reusable
	    && ([NSDate timeIntervalSinceReferenceDate] - start) < 10.0);
          if (r != 1)
            {
              ok = NO;
            }
        }
    }
  if (YES == setup)
    {
      setup = NO;
      [self _freeState];
    }
  return ok;
}

- (void) finalize
{
  [self disconnect: NO];
  [super finalize];
}

- (NSString*) hostName
{
  if (outgoing)
    {
      return [opts objectForKey: GSTLSServerName];
    }
  return nil;
}

- (id) initWithOptions: (NSDictionary*)options
             direction: (BOOL)isOutgoing
             transport: (void*)ioHandle
                  push: (GSTLSIOW)push
                  pull: (GSTLSIOR)pull
{
  if (nil != (self = [super init]))
    {
      GSSChannelState   *st;
      GSTLSCredentials	*cr;
      NSString  	*ca;
      NSString  	*dca;
      NSString  	*rv;
      NSString  	*drv;
      NSString  	*cf;
      NSString  	*ck;
      NSString  	*cp;
      NSString  	*pri;
      NSString  	*str;
      BOOL      	trust;
      BOOL      	verify;
      DWORD             protocols = 0;  // Zero means system defaults
      SECURITY_STATUS   s;

      /* Set this early because it is needed in debug output during init.
       */
      handle = ioHandle;
      pushFunc = push;
      pullFunc = pull;

      created = [NSDate timeIntervalSinceReferenceDate];
      opts = [options copy];
      outgoing = isOutgoing ? YES : NO;

      if (YES == outgoing)
        {
          verify = verifyServer;        // Verify connection to remote server
        }
      else
        {
          verify = verifyClient;        // Verify certificate of remote client
        }
      str = [opts objectForKey: GSTLSVerify];
      if (nil != str)
        {
          verify = [str boolValue];
        }

      debug = (globalDebug > 0) ? YES : NO;
      if (NO == debug)
        {
          debug = [[opts objectForKey: GSTLSDebug] boolValue];
        }

      pri = [opts objectForKey: NSStreamSocketSecurityLevelKey];
      str = [opts objectForKey: GSTLSPriority];
      if (nil == pri && nil == str)
        {
          str = priority;       // Default setting
        }
      if (YES == [str isEqual: @"SSLv3"])
        {
          pri = NSStreamSocketSecurityLevelSSLv3;
          str = nil;
        }
      else if (YES == [str isEqual: @"TLSv1"])
        {
          pri = NSStreamSocketSecurityLevelTLSv1;
          str = nil;
        }
      if (nil != str)
        {
          GSOnceMLog(@"GSTLSPriority is a GNUTLS setting and is ignored"
            @" when using SChannel ... the system defaults are used");
        }
      else if ([pri isEqual: NSStreamSocketSecurityLevelNone] == YES)
        {
          GSOnceMLog(@"NSStreamSocketSecurityLevelNone is insecure ..."
            @" not implemented");
          DESTROY(self);
          return nil;
        }
      else if ([pri isEqual: NSStreamSocketSecurityLevelSSLv2] == YES)
        {
          GSOnceMLog(@"NSStreamSocketSecurityLevelSSLv2 is insecure ..."
            @" not implemented");
          DESTROY(self);
          return nil;
        }
      else if ([pri isEqual: NSStreamSocketSecurityLevelSSLv3] == YES)
        {
          protocols = outgoing ? SP_PROT_SSL3_CLIENT : SP_PROT_SSL3_SERVER;
          GSOnceMLog(@"NSStreamSocketSecurityLevelSSLv3 is insecure ..."
            @" please change your code to stop using it");
        }

      cf = [opts objectForKey: GSTLSCertificateFile];

      if (nil == cf && NO == outgoing)
	{
	  /* Server with no certiticate supplied: generate self signed one.
	   */
	  cr = [GSTLSCredentials selfSigned: debug];
	}
      else
	{
	  ca = [opts objectForKey: GSTLSCAFile];
	  dca = caFile;
	  rv = [opts objectForKey: GSTLSRevokeFile];
	  drv = revokeFile;
	  ck = [opts objectForKey: GSTLSCertificateKeyFile];
	  cp =  [opts objectForKey: GSTLSCertificateKeyPassword];

	  cr = [GSTLSCredentials credentialsFromCAFile: ca
					 defaultCAFile: dca
					    revokeFile: rv
				     defaultRevokeFile: drv
				       certificateFile: cf
				    certificateKeyFile: ck
				certificateKeyPassword: cp
					      asClient: outgoing
						 debug: debug];
	}

      if (cr)
        {
	  ASSIGN(credentials, cr);
	}
      else
	{
          RELEASE(self);
          return nil;
        }

      trust = [credentials trust];
      if (YES == verify && NO == trust)
        {
          NSLog(@"You have requested that a TLS/SSL connection be to a remote"
            @" system with a verified certificate, but have provided no trusted"
            @" certificate authorities.");
          NSLog(@"If you did not use the GSTLSCAFile option to specify a file"
            @" containing certificate authorities for a session, and did not"
            @" specify a default file using the GSTLSCAFile user default or"
            @" the GS_TLS_CA_FILE environment variable, then the system will"
            @" have used the Windows certificate store.  Unfortunately, it has"
            @" not been possible to read any trusted certificate authorities"
            @" from the specified locations.");
        }

      st = calloc(1, sizeof(GSSChannelState));
      st->inBuf = [NSMutableData new];
      st->outBuf = [NSMutableData new];
      st->decBuf = [NSMutableData new];
      session = st;

      if (YES == outgoing)
        {
          str = [opts objectForKey: GSTLSServerName];
          if ([str length] > 0)
            {
              st->target = newWide(str);
              if (debug)
                {
                  NSLog(@"%p %@: set to '%@'", handle, GSTLSServerName, str);
                }
            }
          else if (debug)
            {
              NSLog(@"%p %@: not set", handle, GSTLSServerName);
            }
        }

      s = acquireCredentials(&st->cred, outgoing, protocols,
        [credentials _certificate]);
      if (SEC_E_OK != s)
        {
          NSLog(@"%p unable to set up TLS credentials: %@",
            handle, secStatusString(s));
          DESTROY(self);
          return nil;
        }
      st->haveCred = YES;
      setup = YES;
    }

  return self;
}

- (BOOL) handshake
{
  NSString      *str;
  BOOL          requireVerified;
  int           ret;

  if (YES == active || NO == setup)
    {
      return YES;       // Handshake completed or impossible.
    }

  handshake = YES;
  ret = [self _handshakeStep];
  if (0 == ret)
    {
      setTLSErrno(EAGAIN);
      return NO;        // Need to wait for I/O and retry.
    }
  if (ret < 0)
    {
      GSSChannelState   *st = (GSSChannelState*)session;

      if (nil == problem)
        {
          ASSIGN(problem, @"TLS handshake failure");
        }
      if (debug || NO == st->quiet)
        {
          NSLog(@"%p in handshake: %@", handle, problem);
        }
      [self disconnect: NO];
      return YES;       // Failed ... not active.
    }

  active = YES;         // The TLS session is now active.
  handshake = NO;       // Handshake is over.

  if (YES == outgoing)
    {
      requireVerified = verifyServer;  // Verify remote server certificate?
    }
  else
    {
      requireVerified = verifyClient;  // Verify remote client certificate?
    }
  str = [opts objectForKey: GSTLSVerify];
  if (nil != str)
    {
      requireVerified = [str boolValue];
    }

  /* We always try verification (and can report failure).
   * The requireVerified flag controls whether a verification failure
   * results in disconnect.
   */
  if (globalDebug > 1)
    {
      NSLog(@"%p trying verify:\n%@", handle, [self sessionInfo]);
    }
  ret = [self verify];
  if (ret < 0)
    {
      if (globalDebug > 1
        || (requireVerified && globalDebug > 0)
        || YES == [[opts objectForKey: GSTLSDebug] boolValue])
        {
          NSLog(@"%p unable to verify SSL connection - %@", handle, problem);
          NSLog(@"%p failed verify:\n%@", handle, [self sessionInfo]);
        }
      if (requireVerified)
        {
          [self disconnect: NO];
        }
      else if (outgoing && nil == [opts objectForKey: GSTLSVerify])
        {
          /* We notify about verification failure on outgoing connections
           * if the failure was ignored, unless it was specifically turned
           * off by the app (GSTLSVerify set to NO).
           */
          [[NSNotificationCenter defaultCenter]
            postNotificationName: GSTLSVerifyFailedNotification
                          object: self];
        }
    }
  else if (globalDebug > 1)
    {
      NSLog(@"%p succeeded verify:\n%@", handle, [self sessionInfo]);
    }
  return YES;           // Handshake complete
}

- (NSString*) issuer
{
  return issuer;
}

- (NSDictionary*) options
{
  return opts;
}

- (NSString*) owner
{
  return owner;
}

- (size_t) pending
{
  GSSChannelState       *st = (GSSChannelState*)session;
  size_t                avail;

  if (NULL == st || NO == active)
    {
      return 0;
    }
  if (st->decOff == [st->decBuf length])
    {
      /* Decrypting may not consume more network data, but ensures that
       * data already read from the network is reported.
       */
      [self _decrypt];
    }
  avail = [st->decBuf length] - st->decOff;
  if (0 == avail && (st->failed || st->peerClosed))
    {
      /* Report the connection as readable so that the end of file or
       * error is picked up by a read.
       */
      avail = 1;
    }
  return avail;
}

- (NSString*) problem
{
  return problem;
}

- (NSInteger) read: (void*)buf length: (NSUInteger)len
{
  GSSChannelState       *st = (GSSChannelState*)session;

  if (NULL == st || NO == active)
    {
      setTLSErrno(EBADF);
      return -1;
    }
  if (0 == len)
    {
      return 0;
    }
  for (;;)
    {
      NSUInteger        avail;
      int               r;

      if (YES == st->renegotiate)
        {
          r = [self _handshakeStep];
          if (0 == r)
            {
              setTLSErrno(EAGAIN);
              return -1;
            }
          if (r < 0)
            {
              st->failed = YES;
              break;
            }
          st->renegotiate = NO;
        }

      avail = [st->decBuf length] - st->decOff;
      if (avail > 0)
        {
          if (avail > len)
            {
              avail = len;
            }
          memcpy(buf, (const uint8_t*)[st->decBuf bytes] + st->decOff, avail);
          st->decOff += avail;
          if (st->decOff == [st->decBuf length])
            {
              [st->decBuf setLength: 0];
              st->decOff = 0;
            }
          return avail;
        }
      if (YES == st->peerClosed)
        {
          return 0;
        }
      if (YES == st->failed || [self _decrypt] < 0)
        {
          break;
        }
      if ([st->decBuf length] > st->decOff || YES == st->peerClosed
        || YES == st->renegotiate)
        {
          continue;
        }

      r = [self _fill];
      if (-1 == r)
        {
          setTLSErrno(EAGAIN);
          return -1;
        }
      if (0 == r)
        {
          st->peerClosed = YES;     // Closed without a TLS close_notify
          return 0;
        }
      if (r < 0)
        {
          st->failed = YES;
          break;
        }
    }

  if (debug)
    {
      NSLog(@"%p in tls read: %@", handle, problem);
    }
  setTLSErrno(EBADF);
  return -1;
}

- (NSInteger) write: (const void*)buf length: (NSUInteger)len
{
  GSSChannelState       *st = (GSSChannelState*)session;
  SecBuffer             b[4];
  SecBufferDesc         d;
  SECURITY_STATUS       s;
  NSUInteger            off;
  uint8_t               *ptr;
  int                   r;

  if (NULL == st || NO == active || YES == st->failed)
    {
      setTLSErrno(EBADF);
      return -1;
    }

  /* As with gnutls, if a previous write could not be sent completely
   * the caller must retry with the same data, and we report the amount
   * of that data written once the record has been sent.
   */
  r = [self _flush];
  if (0 == r)
    {
      setTLSErrno(EAGAIN);
      return -1;
    }
  if (r < 0)
    {
      goto failed;
    }
  if (st->pendingPlain > 0)
    {
      NSUInteger        done = st->pendingPlain;

      st->pendingPlain = 0;
      return done;
    }
  if (YES == st->renegotiate)
    {
      r = [self _handshakeStep];
      if (0 == r)
        {
          setTLSErrno(EAGAIN);
          return -1;
        }
      if (r < 0)
        {
          goto failed;
        }
      st->renegotiate = NO;
    }
  if (0 == len)
    {
      return 0;
    }

  if (len > st->sizes.cbMaximumMessage)
    {
      len = st->sizes.cbMaximumMessage;
    }
  off = [st->outBuf length];
  [st->outBuf setLength: off + st->sizes.cbHeader + len + st->sizes.cbTrailer];
  ptr = (uint8_t*)[st->outBuf mutableBytes] + off;
  memcpy(ptr + st->sizes.cbHeader, buf, len);
  b[0].BufferType = SECBUFFER_STREAM_HEADER;
  b[0].cbBuffer = st->sizes.cbHeader;
  b[0].pvBuffer = ptr;
  b[1].BufferType = SECBUFFER_DATA;
  b[1].cbBuffer = (ULONG)len;
  b[1].pvBuffer = ptr + st->sizes.cbHeader;
  b[2].BufferType = SECBUFFER_STREAM_TRAILER;
  b[2].cbBuffer = st->sizes.cbTrailer;
  b[2].pvBuffer = ptr + st->sizes.cbHeader + len;
  b[3].BufferType = SECBUFFER_EMPTY;
  b[3].cbBuffer = 0;
  b[3].pvBuffer = NULL;
  d.ulVersion = SECBUFFER_VERSION;
  d.cBuffers = 4;
  d.pBuffers = b;
  s = EncryptMessage(&st->ctxt, 0, &d, 0);
  if (SEC_E_OK != s)
    {
      [st->outBuf setLength: off];
      ASSIGN(problem, secStatusString(s));
      goto failed;
    }
  [st->outBuf setLength: off + b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer];

  r = [self _flush];
  if (0 == r)
    {
      st->pendingPlain = len;
      setTLSErrno(EAGAIN);
      return -1;
    }
  if (r < 0)
    {
      goto failed;
    }
  return len;

failed:
  st->failed = YES;
  if (debug)
    {
      NSLog(@"%p in tls write: %@", handle, problem);
    }
  setTLSErrno(EBADF);
  return -1;
}

- (NSString*) sessionInfo
{
  GSSChannelState               *st = (GSSChannelState*)session;
  NSMutableString               *str;
  SecPkgContext_ConnectionInfo  ci;
  PCCERT_CONTEXT                remote = NULL;

  str = [NSMutableString stringWithCapacity: 2000];
  if (outgoing)
    {
      [str appendFormat: @"- Outgoing session: %p to '%@'\n",
	self, [self hostName]];
    }
  else
    {
      [str appendFormat: @"- Oncoming session: %p\n", self];
    }
  if (NULL == st || NO == st->haveCtxt)
    {
      [str appendString: @"- No TLS context.\n"];
      return str;
    }

  if (SEC_E_OK == QueryContextAttributesW(&st->ctxt,
    SECPKG_ATTR_CONNECTION_INFO, &ci))
    {
      [str appendFormat: _(@"- Protocol: %@\n"), protocolName(ci.dwProtocol)];
      [str appendFormat: _(@"- Cipher strength: %lu bits\n"),
        (unsigned long)ci.dwCipherStrength];
    }
#if     defined(SECPKG_ATTR_CIPHER_INFO)
  {
    SecPkgContext_CipherInfo    info;

    memset(&info, 0, sizeof(info));
    info.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
    if (SEC_E_OK == QueryContextAttributesW(&st->ctxt,
      SECPKG_ATTR_CIPHER_INFO, &info))
      {
        [str appendFormat: _(@"- Cipher suite: %@\n"),
          fromWide(info.szCipherSuite)];
        [str appendFormat: _(@"- Key Exchange: %@\n"),
          fromWide(info.szExchange)];
        [str appendFormat: _(@"- Cipher: %@\n"), fromWide(info.szCipher)];
        [str appendFormat: _(@"- MAC: %@\n"), fromWide(info.szHash)];
      }
  }
#endif

  if (SEC_E_OK == QueryContextAttributesW(&st->ctxt,
    SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote) && NULL != remote)
    {
      [str appendString: _(@"- Peer certificate\n")];
      certInfo(remote, str);
      CertFreeCertificateContext(remote);
    }
  else
    {
      [str appendString: _(@"- Peer provided no certificate.\n")];
    }
  return str;
}

- (int) verify
{
  GSSChannelState       *st = (GSSChannelState*)session;
  PCCERT_CONTEXT        remote = NULL;
  PCCERT_CHAIN_CONTEXT  chain = NULL;
  HCERTSTORE            extra;
  HCERTSTORE            caStore = [credentials _caStore];
  HCERTSTORE            crlStore = [credentials _crlStore];
  CERT_CHAIN_PARA       cp;
  LPSTR                 usage;
  DWORD                 authType;
  DWORD                 err;
  BOOL                  trusted;
  NSMutableString       *ci;
  NSString              *nameList;
  NSString              *str;
  NSArray               *names;
  int                   result = -1;

  if (NULL == st || NO == st->haveCtxt
    || SEC_E_OK != QueryContextAttributesW(&st->ctxt,
      SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote) || NULL == remote)
    {
      ASSIGN(problem, @"TLS verification: no certificate from remote end!");
      if (debug) NSLog(@"%p %@", handle, problem);
      return -1;
    }

  ASSIGN(owner, dnString(&remote->pCertInfo->Subject));
  ASSIGN(issuer, dnString(&remote->pCertInfo->Issuer));
  ci = [NSMutableString stringWithCapacity: 2000];
  certInfo(remote, ci);

  /* Build the chain using intermediates sent by the peer as well as the
   * configured certificate authorities.
   */
  extra = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
  CertAddStoreToCollection(extra, remote->hCertStore, 0, 0);
  if (NULL != caStore)
    {
      CertAddStoreToCollection(extra, caStore, 0, 0);
    }
  if (outgoing)
    {
      usage = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
      authType = AUTHTYPE_SERVER;
    }
  else
    {
      usage = (LPSTR)szOID_PKIX_KP_CLIENT_AUTH;
      authType = AUTHTYPE_CLIENT;
    }
  memset(&cp, 0, sizeof(cp));
  cp.cbSize = sizeof(cp);
  cp.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
  cp.RequestedUsage.Usage.cUsageIdentifier = 1;
  cp.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
  if (!CertGetCertificateChain(NULL, remote, NULL, extra, &cp, 0, NULL,
    &chain))
    {
      str = [NSString stringWithFormat:
        @"TLS verification: error %@", secStatusString(GetLastError())];
      ASSIGN(problem, str);
      goto done;
    }

  err = chainPolicyError(chain, authType, 0, NULL);
  trusted = (0 == err && NO == [credentials _exclusive]) ? YES : NO;
  if (NO == trusted && NULL != caStore
    && (0 == err || CERT_E_UNTRUSTEDROOT == err || CERT_E_CHAINING == err))
    {
      /* Accept chains anchored at one of our own trusted authorities.
       */
      err = chainPolicyError(chain, authType,
        SECURITY_FLAG_IGNORE_UNKNOWN_CA, NULL);
      if (0 == err)
        {
          if (chainHasAnchor(chain, caStore))
            {
              trusted = YES;
            }
          else
            {
              err = CERT_E_UNTRUSTEDROOT;
            }
        }
    }
  if (NO == trusted)
    {
      NSString  *reason;

      switch (err)
        {
          case CERT_E_UNTRUSTEDROOT:
          case CERT_E_CHAINING:
            reason = @", certificate hasn't got a known issuer";
            break;
          case CERT_E_EXPIRED:
            reason = @", certificate has expired or is not yet activated";
            break;
          case CRYPT_E_REVOKED:
            reason = @", certificate has been revoked";
            break;
          default:
            reason = [NSString stringWithFormat: @", %@",
              secStatusString(err)];
            break;
        }
      str = [NSString stringWithFormat:
        @"TLS verification: remote certificate is not trusted%@.", reason];
      ASSIGN(problem, str);
      goto done;
    }
  if (NULL != crlStore && chainIsRevoked(chain, crlStore))
    {
      ASSIGN(problem, @"TLS verification: remote certificate is not trusted,"
        @" certificate has been revoked.");
      goto done;
    }

  nameList = [opts objectForKey: GSTLSRemoteHosts];
  if (nil == nameList)
    {
      /* If nothing is specified, assume the connection host name
       * (if any) should be used for verification.
       */
      nameList = [opts objectForKey: GSTLSServerName];
      if ([nameList length] > 0)
        {
          names = [NSArray arrayWithObject: nameList];
        }
      else
        {
          names = nil;
        }
    }
  else
    {
      /* The string is a comma separated list of permitted host names.
       * If explicitly set to be empty, no host verification is done.
       */
      names = [nameList componentsSeparatedByString: @","];
      if ([names count] == 0)
        {
          names = nil;
        }
    }

  if (nil != names)
    {
      NSEnumerator      *enumerator = [names objectEnumerator];
      BOOL              found = NO;
      NSString          *name;

      while (NO == found && nil != (name = [enumerator nextObject]))
        {
          WCHAR *w = newWide(name);

          err = chainPolicyError(chain, AUTHTYPE_SERVER,
            SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_WRONG_USAGE
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, w);
          free(w);
          if (CERT_E_CN_NO_MATCH != err)
            {
              found = YES;
            }
        }
      if (NO == found)
        {
          str = [NSString stringWithFormat:
            @"TLS verification: hostname does not match '%@' in %@",
            nameList, ci];
          ASSIGN(problem, str);
          goto done;
        }
    }

  names = [opts objectForKey: GSTLSIssuers];
  if ([names isKindOfClass: [NSArray class]])
    {
      if (nil == issuer || NO == [names containsObject: issuer])
        {
          str = [NSString stringWithFormat:
            @"TLS verification: issuer does not match '%@' in %@",
            names, ci];
          ASSIGN(problem, str);
          goto done;
        }
    }

  names = [opts objectForKey: GSTLSOwners];
  if ([names isKindOfClass: [NSArray class]])
    {
      if (nil == owner || NO == [names containsObject: owner])
        {
          str = [NSString stringWithFormat:
            @"TLS verification: owner does not match '%@' in %@",
            names, ci];
          ASSIGN(problem, str);
          goto done;
        }
    }

  result = 0;   // Verified

done:
  if (result < 0 && debug)
    {
      NSLog(@"%p %@", handle, problem);
    }
  if (NULL != chain)
    {
      CertFreeCertificateChain(chain);
    }
  CertCloseStore(extra, 0);
  CertFreeCertificateContext(remote);
  return result;
}

@end

#endif  /* HAVE_GNUTLS */

#endif

