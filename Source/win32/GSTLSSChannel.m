/** Implementation of TLS using the native Windows SChannel API
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

#import "common.h"

#if     defined(HAVE_SCHANNEL)

#import "Foundation/NSArray.h"
#import "Foundation/NSData.h"
#import "Foundation/NSDictionary.h"
#import "Foundation/NSEnumerator.h"
#import "Foundation/NSException.h"
#import "Foundation/NSFileManager.h"
#import "Foundation/NSLock.h"
#import "Foundation/NSNotification.h"
#import "Foundation/NSProcessInfo.h"
#import "Foundation/NSStream.h"
#import "Foundation/NSUserDefaults.h"
#import "Foundation/NSValue.h"
#import "GNUstepBase/GSTLS.h"
#import "../GSTLSSChannel.h"

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS     // Exposes SCH_CREDENTIALS
#include <subauth.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <wchar.h>

/* These are normally provided by wininet.h
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


/* Configuration from user defaults and the environment (as for GNUTLS).
 */
static NSString *caFile = nil;
static BOOL     verifyClient = NO;
static BOOL     verifyServer = YES;
static int      globalDebug = 0;
static NSString *priority = nil;

static NSLock                   *fileLock = nil;
static NSMutableDictionary      *fileMap = nil;
static NSLock                   *credentialsLock = nil;
static NSMutableDictionary      *credentialsCache = nil;

/* Private keys which Windows persisted for us (SChannel can not use
 * ephemeral keys) and which must be deleted when no longer needed.
 */
static NSLock                   *keyLock = nil;
static NSMutableArray           *liveKeys = nil;
static LONG                     keyCounter = 0;


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
statusString(DWORD s)
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

/* Returns a distinguished name in RFC4514 form (as GNUTLS does).
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

/* Adds the certificates in a PEM file (or a single DER certificate) to
 * the store, returning the number added.
 */
static int
addCertificates(HCERTSTORE store, NSData *data, NSString *path)
{
  NSString      *s;
  NSRange       r;
  int           count = 0;

  s = AUTORELEASE([[NSString alloc] initWithData: data
                                        encoding: NSISOLatin1StringEncoding]);
  r = [s rangeOfString: @"-----BEGIN CERTIFICATE-----"];
  if (0 == r.length)
    {
      if (CertAddEncodedCertificateToStore(store, GS_ENCODING,
        [data bytes], (DWORD)[data length], CERT_STORE_ADD_USE_EXISTING, NULL))
        {
          count++;
        }
      return count;
    }
  while (r.length > 0)
    {
      NSUInteger        start = NSMaxRange(r);
      NSUInteger        length = [s length];
      NSRange           e;
      NSData            *der;

      e = [s rangeOfString: @"-----END CERTIFICATE-----" options: 0
                     range: NSMakeRange(start, length - start)];
      if (0 == e.length)
        {
          break;
        }
      der = [[NSData alloc] initWithBase64EncodedString:
        [s substringWithRange: NSMakeRange(start, e.location - start)]
        options: NSDataBase64DecodingIgnoreUnknownCharacters];
      if (nil != der && CertAddEncodedCertificateToStore(store, GS_ENCODING,
        [der bytes], (DWORD)[der length], CERT_STORE_ADD_USE_EXISTING, NULL))
        {
          count++;
        }
      else
        {
          NSLog(@"Unable to parse certificate in '%@'", path);
        }
      RELEASE(der);
      start = NSMaxRange(e);
      r = [s rangeOfString: @"-----BEGIN CERTIFICATE-----" options: 0
                     range: NSMakeRange(start, length - start)];
    }
  return count;
}

/* A key record is an array of provider name, container name, provider
 * type (zero for CNG) and key flags.
 */
static NSArray *
keyRecord(NSString *prov, NSString *container, DWORD type, DWORD flags)
{
  return [NSArray arrayWithObjects: prov, container,
    [NSNumber numberWithUnsignedLong: type],
    [NSNumber numberWithUnsignedLong: flags], nil];
}

static void
deleteKey(NSArray *record)
{
  WCHAR *prov = newWide([record objectAtIndex: 0]);
  WCHAR *name = newWide([record objectAtIndex: 1]);
  DWORD type = (DWORD)[[record objectAtIndex: 2] unsignedLongValue];
  DWORD flags = (DWORD)[[record objectAtIndex: 3] unsignedLongValue];

  if (0 == type)
    {
      NCRYPT_PROV_HANDLE        p = 0;
      NCRYPT_KEY_HANDLE         k = 0;

      if (ERROR_SUCCESS == NCryptOpenStorageProvider(&p, prov, 0))
        {
          if (ERROR_SUCCESS == NCryptOpenKey(p, &k, name, 0,
            flags & NCRYPT_MACHINE_KEY_FLAG))
            {
              NCryptDeleteKey(k, 0);
            }
          NCryptFreeObject(p);
        }
    }
  else
    {
      HCRYPTPROV        h = 0;

      CryptAcquireContextW(&h, name, prov, type,
        CRYPT_DELETEKEYSET | (flags & CRYPT_MACHINE_KEYSET));
    }
  free(prov);
  free(name);
}

static void
trackKey(NSArray *record, NSMutableArray *owned)
{
  [owned addObject: record];
  [keyLock lock];
  [liveKeys addObject: record];
  [keyLock unlock];
}

static void
releaseKeys(NSArray *records)
{
  NSEnumerator  *e = [records objectEnumerator];
  NSArray       *r;

  while (nil != (r = [e nextObject]))
    {
      deleteKey(r);
      [keyLock lock];
      [liveKeys removeObjectIdenticalTo: r];
      [keyLock unlock];
    }
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

    /* Needed for TLS 1.3 (Windows 10 1809 and later), fails on older
     * systems where we fall back to SCHANNEL_CRED.
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


@implementation GSTLSObject

+ (void) _defaultsChanged: (NSNotification*)n
{
  NSUserDefaults        *defs = [NSUserDefaults standardUserDefaults];
  NSDictionary          *env = [[NSProcessInfo processInfo] environment];
  NSString              *str;

  str = [defs stringForKey: GSTLSPriority];
  ASSIGN(priority, ([str length] > 0) ? str : nil);

  str = [defs stringForKey: GSTLSCAFile];
  if (nil == str)
    {
      str = [env objectForKey: @"GS_TLS_CA_FILE"];
      if (nil == str)
        {
          str = [env objectForKey: @"SSL_CERT_FILE"];
        }
    }
  ASSIGN(caFile, standardizedPath(str));

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
}

+ (void) atExit
{
  NSArray       *keys;

  /* Persisted private keys must not outlive the process.
   */
  [keyLock lock];
  keys = AUTORELEASE([liveKeys copy]);
  [keyLock unlock];
  releaseKeys(keys);
  if ([NSObject shouldCleanUp])
    {
      DESTROY(credentialsCache);
      DESTROY(credentialsLock);
      DESTROY(fileMap);
      DESTROY(fileLock);
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
  result = RETAIN([fileMap objectForKey: fileName]);
  [fileLock unlock];
  if (nil == result)
    {
      return [NSData dataWithContentsOfFile: fileName];
    }
  return AUTORELEASE(result);
}

+ (void) initialize
{
  if ([GSTLSObject class] == self && nil == fileLock)
    {
      [self registerAtExit];
      fileLock = [NSLock new];
      fileMap = [NSMutableDictionary new];
      credentialsLock = [NSLock new];
      credentialsCache = [NSMutableDictionary new];
      keyLock = [NSLock new];
      liveKeys = [NSMutableArray new];
      [[NSNotificationCenter defaultCenter]
        addObserver: self
           selector: @selector(_defaultsChanged:)
               name: NSUserDefaultsDidChangeNotification
             object: nil];
      [self _defaultsChanged: nil];
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
  if (nil == data)
    {
      [fileMap removeObjectForKey: fileName];
    }
  else
    {
      [fileMap setObject: data forKey: fileName];
    }
  [fileLock unlock];
}

@end


/* Trusted authorities and our own certificate (with private key).
 */
@interface      GSTLSCredentials : GSTLSObject
{
@public
  NSTimeInterval        when;
  NSString              *name;
  NSMutableArray        *keys;          // Key records to delete
  BOOL                  trust;
  BOOL                  exclusive;      // Only caStore roots are trusted
  PCCERT_CONTEXT        cert;
  HCERTSTORE            certStore;
  HCERTSTORE            caStore;
}
+ (GSTLSCredentials*) credentialsFromCAFile: (NSString*)ca
                              defaultCAFile: (NSString*)dca
                            certificateFile: (NSString*)cf
                                   password: (NSString*)cp
                                      debug: (BOOL)debug;
+ (GSTLSCredentials*) selfSigned: (BOOL)debug;
@end

@implementation GSTLSCredentials

static GSTLSCredentials *selfSignedCredentials = nil;

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
      GSTLSCredentials   *cred = [credentialsCache objectForKey: key];

      if (now - cred->when > 300.0)
        {
          [credentialsCache removeObjectForKey: key];
        }
    }
  [credentialsLock unlock];
}

+ (void) initialize
{
  if ([GSTLSCredentials class] == self)
    {
      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(housekeeping:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (GSTLSCredentials*) selfSigned: (BOOL)debug
{
  GSTLSCredentials              *c;
  NCRYPT_PROV_HANDLE            prov = 0;
  NCRYPT_KEY_HANDLE             key = 0;
  CERT_NAME_BLOB                subject;
  CRYPT_KEY_PROV_INFO           kpi;
  CRYPT_ALGORITHM_IDENTIFIER    alg;
  SYSTEMTIME                    end;
  FILETIME                      ft;
  ULARGE_INTEGER                u;
  PCCERT_CONTEXT                cert = NULL;
  BYTE                          dn[256];
  DWORD                         bits = 2048;
  NSString                      *keyName;
  WCHAR                         *wname;
  SECURITY_STATUS               s;

  [credentialsLock lock];
  c = RETAIN(selfSignedCredentials);
  [credentialsLock unlock];
  if (nil != c)
    {
      return AUTORELEASE(c);
    }

  keyName = [NSString stringWithFormat: @"GNUstep-GSTLS-%lu-%ld",
    (unsigned long)GetCurrentProcessId(),
    (long)InterlockedIncrement(&keyCounter)];
  wname = newWide(keyName);
  s = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
  if (ERROR_SUCCESS == s)
    {
      s = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM,
        wname, 0, NCRYPT_OVERWRITE_KEY_FLAG);
    }
  if (ERROR_SUCCESS == s)
    {
      s = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&bits, sizeof(bits), 0);
    }
  if (ERROR_SUCCESS == s)
    {
      s = NCryptFinalizeKey(key, 0);
    }
  if (ERROR_SUCCESS == s)
    {
      subject.cbData = sizeof(dn);
      subject.pbData = dn;
      if (!CertStrToNameW(X509_ASN_ENCODING,
        L"CN=SelfSigned, O=SelfSigned, C=EX", CERT_X500_NAME_STR, NULL,
        dn, &subject.cbData, NULL))
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
      cert = CertCreateSelfSignCertificate(
        (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)key,
        &subject, 0, &kpi, &alg, NULL, &end, NULL);
      if (NULL == cert)
        {
          s = (SECURITY_STATUS)GetLastError();
        }
    }
  if (key) NCryptFreeObject(key);
  if (prov) NCryptFreeObject(prov);
  free(wname);

  c = [self new];
  c->name = @"self-signed";
  c->when = [NSDate timeIntervalSinceReferenceDate];
  c->keys = [NSMutableArray new];
  trackKey(keyRecord(fromWide(MS_KEY_STORAGE_PROVIDER), keyName, 0, 0),
    c->keys);
  if (NULL == cert)
    {
      NSLog(@"Failed to make self-signed certificate: %@",
        statusString((DWORD)s));
      RELEASE(c);
      return nil;
    }
  c->cert = cert;
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

/* Loads a PKCS#12 file and returns the first certificate with a private
 * key, recording the keys Windows persisted during the import.
 */
- (BOOL) _loadPKCS12: (NSString*)cf password: (NSString*)cp
{
  CRYPT_DATA_BLOB       blob;
  NSData                *data;
  WCHAR                 *wpass;
  PCCERT_CONTEXT        c = NULL;

  data = [[self class] dataForTLSFile: cf];
  if (nil == data)
    {
      NSLog(@"Unable to read certificate file '%@'", cf);
      return NO;
    }
  blob.cbData = (DWORD)[data length];
  blob.pbData = (BYTE*)[data bytes];
  if (!PFXIsPFXBlob(&blob))
    {
      NSLog(@"The certificate file '%@' is not in PKCS#12 (.pfx) format,"
        @" which is required with the SChannel TLS implementation", cf);
      return NO;
    }
  wpass = newWide(nil == cp ? @"" : cp);
  certStore = PFXImportCertStore(&blob, wpass, CRYPT_USER_KEYSET);
  if (NULL == certStore && nil == cp)
    {
      certStore = PFXImportCertStore(&blob, NULL, CRYPT_USER_KEYSET);
    }
  SecureZeroMemory(wpass, wcslen(wpass) * sizeof(WCHAR));
  free(wpass);
  if (NULL == certStore)
    {
      NSLog(@"Unable to load certificate file '%@': %@",
        cf, statusString(GetLastError()));
      return NO;
    }

  while (NULL != (c = CertEnumCertificatesInStore(certStore, c)))
    {
      CRYPT_KEY_PROV_INFO       *kpi;
      DWORD                     len = 0;

      if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID,
        NULL, &len))
        {
          continue;
        }
      kpi = malloc(len);
      if (CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID,
        kpi, &len))
        {
          trackKey(keyRecord(fromWide(kpi->pwszProvName),
            fromWide(kpi->pwszContainerName), kpi->dwProvType,
            kpi->dwFlags), keys);
          if (NULL == cert)
            {
              cert = CertDuplicateCertificateContext(c);
            }
        }
      free(kpi);
    }
  if (NULL == cert)
    {
      NSLog(@"No certificate with a private key found in '%@'", cf);
      return NO;
    }
  return YES;
}

+ (GSTLSCredentials*) credentialsFromCAFile: (NSString*)ca
                              defaultCAFile: (NSString*)dca
                            certificateFile: (NSString*)cf
                                   password: (NSString*)cp
                                      debug: (BOOL)debug
{
  GSTLSCredentials      *c;
  NSString              *k;

  ca = standardizedPath(ca);
  cf = standardizedPath(cf);
  k = [NSString stringWithFormat: @"%@:%@:%@",
    (nil == ca) ? @"" : ca, (nil == dca) ? @"" : dca,
    (nil == cf) ? @"" : cf];

  [credentialsLock lock];
  c = RETAIN([credentialsCache objectForKey: k]);
  [credentialsLock unlock];
  if (nil != c)
    {
      if (debug)
        {
          NSLog(@"Re-used credentials %p for '%@'", c, k);
        }
      return AUTORELEASE(c);
    }

  c = [self new];
  c->name = [k copy];
  c->when = [NSDate timeIntervalSinceReferenceDate];
  c->keys = [NSMutableArray new];

  if ([dca length] > 0 || [ca length] > 0)
    {
      c->caStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
        CERT_STORE_CREATE_NEW_FLAG, NULL);
    }

  /* A default CA file replaces the operating system trust store.
   */
  if ([dca length] > 0)
    {
      NSData    *data = [self dataForTLSFile: dca];
      int       n = 0;

      c->exclusive = YES;
      if (nil == data)
        {
          NSLog(@"Problem loading trusted authorities from %@", dca);
        }
      else
        {
          n = addCertificates(c->caStore, data, dca);
        }
      if (n > 0)
        {
          c->trust = YES;
        }
      if (debug)
        {
          NSLog(@"Default trusted authorities (from %@): %d", dca, n);
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

  if ([ca length] > 0)
    {
      NSData    *data = [self dataForTLSFile: ca];
      int       n = 0;

      if (nil == data)
        {
          NSLog(@"Problem loading trusted authorities from %@", ca);
        }
      else
        {
          n = addCertificates(c->caStore, data, ca);
        }
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

  if (nil != cf && NO == [c _loadPKCS12: cf password: cp])
    {
      RELEASE(c);
      return nil;
    }

  if (debug)
    {
      NSLog(@"%@ created credentials %p for '%@'", self, c, k);
    }
  [credentialsLock lock];
  [credentialsCache setObject: c forKey: k];
  [credentialsLock unlock];
  return AUTORELEASE(c);
}

- (void) dealloc
{
  if (NULL != cert)
    {
      CertFreeCertificateContext(cert);
    }
  if (NULL != certStore)
    {
      CertCloseStore(certStore, 0);
    }
  if (NULL != caStore)
    {
      CertCloseStore(caStore, 0);
    }
  releaseKeys(keys);
  DESTROY(keys);
  DESTROY(name);
  [super dealloc];
}

@end


@implementation GSTLSSession

- (BOOL) active
{
  return active;
}

- (NSTimeInterval) age
{
  return [NSDate timeIntervalSinceReferenceDate] - created;
}

- (void) _freeState
{
  GSSChannelState       *st = (GSSChannelState*)state;

  if (NULL != st)
    {
      state = NULL;
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
  [self disconnect: NO];
  [self _freeState];
  DESTROY(opts);
  DESTROY(credentials);
  DESTROY(problem);
  DESTROY(issuer);
  DESTROY(owner);
  [super dealloc];
}

/* Sends queued encrypted data.  Returns 1 when everything has been sent,
 * 0 if the transport would block, -1 on failure.
 */
- (int) _flush
{
  GSSChannelState       *st = (GSSChannelState*)state;

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
  GSSChannelState       *st = (GSSChannelState*)state;
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

/* Discards the consumed part of the input, keeping data SChannel reported
 * as extra (unprocessed).
 */
static void
keepExtra(GSSChannelState *st, SecBuffer *b)
{
  if (SECBUFFER_EXTRA == b->BufferType && b->cbBuffer > 0)
    {
      uint8_t           *ptr = [st->inBuf mutableBytes];
      NSUInteger        len = [st->inBuf length];

      memmove(ptr, ptr + len - b->cbBuffer, b->cbBuffer);
      [st->inBuf setLength: b->cbBuffer];
    }
  else
    {
      [st->inBuf setLength: 0];
    }
}

static void
setTokenInput(SecBufferDesc *desc, SecBuffer *b, NSMutableData *d)
{
  b[0].BufferType = SECBUFFER_TOKEN;
  b[0].cbBuffer = (ULONG)[d length];
  b[0].pvBuffer = [d mutableBytes];
  b[1].BufferType = SECBUFFER_EMPTY;
  b[1].cbBuffer = 0;
  b[1].pvBuffer = NULL;
  desc->ulVersion = SECBUFFER_VERSION;
  desc->cBuffers = 2;
  desc->pBuffers = b;
}

/* Calls InitializeSecurityContext or AcceptSecurityContext with the
 * supplied input, queueing any output to be sent to the peer.
 */
- (SECURITY_STATUS) _negotiate: (SecBufferDesc*)inDesc
{
  GSSChannelState       *st = (GSSChannelState*)state;
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
  GSSChannelState       *st = (GSSChannelState*)state;
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
              ASSIGN(problem, statusString(s));
              return -1;
            }
          return 1;
        }

      if (NO == st->haveCtxt && YES == outgoing)
        {
          s = [self _negotiate: NULL];        // Client hello
          if (SEC_I_CONTINUE_NEEDED != s)
            {
              ASSIGN(problem, statusString(s));
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

      setTokenInput(&inDesc, inb, st->inBuf);
      s = [self _negotiate: &inDesc];
      if (SEC_E_INCOMPLETE_MESSAGE == s)
        {
          st->needInput = YES;
          continue;
        }
      if (SEC_I_INCOMPLETE_CREDENTIALS == s && 0 == incompleteCredentials++)
        {
          continue;     // Proceed without the requested client certificate
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

      [self _flush];    // Try to send any alert
      ASSIGN(problem, statusString(s));
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

/* Handles a post-handshake message (eg. a TLS 1.3 session ticket) or a
 * renegotiation request by passing the remaining (encrypted) input to
 * SChannel as a handshake token.
 */
- (int) _postHandshake
{
  GSSChannelState       *st = (GSSChannelState*)state;
  SecBuffer             inb[2];
  SecBufferDesc         inDesc;
  SECURITY_STATUS       s;

  setTokenInput(&inDesc, inb, st->inBuf);
  s = [self _negotiate: &inDesc];
  if (SEC_E_OK == s || SEC_I_CONTINUE_NEEDED == s)
    {
      keepExtra(st, &inb[1]);
    }
  if (SEC_E_OK == s)
    {
      [self _flush];
      return 0;
    }
  if (SEC_I_CONTINUE_NEEDED == s || SEC_E_INCOMPLETE_MESSAGE == s)
    {
      st->renegotiate = YES;
      st->hsDone = NO;
      st->needInput = (SEC_E_INCOMPLETE_MESSAGE == s) ? YES : NO;
      return 0;
    }
  ASSIGN(problem, statusString(s));
  return -1;
}

/* Decrypts as many complete records as are buffered.
 * Returns 0 on success, -1 on a fatal error.
 */
- (int) _decrypt
{
  GSSChannelState       *st = (GSSChannelState*)state;

  while ([st->inBuf length] > 0 && NO == st->peerClosed
    && NO == st->renegotiate && NO == st->failed)
    {
      SecBuffer         b[4];
      SecBufferDesc     d;
      SECURITY_STATUS   s;
      SecBuffer         *data = NULL;
      SecBuffer         *extra = NULL;
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
          ASSIGN(problem, statusString(s));
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
      if (NULL != data && data->cbBuffer > 0 && SEC_E_OK == s)
        {
          if (st->decOff == [st->decBuf length])
            {
              [st->decBuf setLength: 0];
              st->decOff = 0;
            }
          [st->decBuf appendBytes: data->pvBuffer length: data->cbBuffer];
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
      else if (SEC_I_RENEGOTIATE == s && [self _postHandshake] < 0)
        {
          st->failed = YES;
          return -1;
        }
    }
  return 0;
}

- (BOOL) disconnect: (BOOL)reusable
{
  GSSChannelState       *st = (GSSChannelState*)state;
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
              [self _negotiate: NULL];        // Generates close_notify
            }
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
      /* State is freed in -dealloc since we may be called re-entrantly
       * (from a transport callback) while it is in use.
       */
      setup = NO;
    }
  return ok;
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
      NSString  	*cf;
      NSString  	*pri;
      NSString  	*str;
      BOOL      	verify;
      DWORD             protocols = 0;  // Zero means system defaults
      SECURITY_STATUS   s;

      handle = ioHandle;
      pushFunc = push;
      pullFunc = pull;
      created = [NSDate timeIntervalSinceReferenceDate];
      opts = [options copy];
      outgoing = isOutgoing ? YES : NO;

      verify = outgoing ? verifyServer : verifyClient;
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
          str = priority;
        }
      if ([str isEqual: @"SSLv3"])
        {
          pri = NSStreamSocketSecurityLevelSSLv3;
          str = nil;
        }
      else if ([str isEqual: @"TLSv1"])
        {
          pri = NSStreamSocketSecurityLevelTLSv1;
          str = nil;
        }
      if (nil != str)
        {
          GSOnceMLog(@"GSTLSPriority is not supported by the SChannel TLS"
            @" implementation ... the system defaults are used");
        }
      else if ([pri isEqual: NSStreamSocketSecurityLevelNone]
        || [pri isEqual: NSStreamSocketSecurityLevelSSLv2])
        {
          GSOnceMLog(@"%@ is insecure ... not implemented", pri);
          DESTROY(self);
          return nil;
        }
      else if ([pri isEqual: NSStreamSocketSecurityLevelSSLv3])
        {
          protocols = outgoing ? SP_PROT_SSL3_CLIENT : SP_PROT_SSL3_SERVER;
          GSOnceMLog(@"NSStreamSocketSecurityLevelSSLv3 is insecure ..."
            @" please change your code to stop using it");
        }

      cf = [opts objectForKey: GSTLSCertificateFile];
      if (nil == cf && NO == outgoing)
	{
	  cr = [GSTLSCredentials selfSigned: debug];
	}
      else
	{
          cr = [GSTLSCredentials
            credentialsFromCAFile: [opts objectForKey: GSTLSCAFile]
                    defaultCAFile: caFile
                  certificateFile: cf
                         password: [opts objectForKey:
                           GSTLSCertificateKeyPassword]
                            debug: debug];
	}
      if (nil == cr)
	{
          DESTROY(self);
          return nil;
        }
      ASSIGN(credentials, cr);

      if (YES == verify && NO == cr->trust)
        {
          NSLog(@"You have requested that a TLS/SSL connection be to a remote"
            @" system with a verified certificate, but have provided no"
            @" trusted certificate authorities.");
        }

      st = calloc(1, sizeof(GSSChannelState));
      st->inBuf = [NSMutableData new];
      st->outBuf = [NSMutableData new];
      st->decBuf = [NSMutableData new];
      state = st;

      if (YES == outgoing)
        {
          str = [opts objectForKey: GSTLSServerName];
          if ([str length] > 0)
            {
              st->target = newWide(str);
            }
          if (debug)
            {
              NSLog(@"%p %@: %@", handle, GSTLSServerName,
                [str length] > 0 ? str : @"not set");
            }
        }

      s = acquireCredentials(&st->cred, outgoing, protocols, cr->cert);
      if (SEC_E_OK != s)
        {
          NSLog(@"%p unable to set up TLS credentials: %@",
            handle, statusString(s));
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

  AUTORELEASE(RETAIN(self));    // Callbacks may release us
  handshake = YES;
  ret = [self _handshakeStep];
  if (0 == ret)
    {
      setTLSErrno(EAGAIN);
      return NO;
    }
  if (ret < 0)
    {
      GSSChannelState   *st = (GSSChannelState*)state;

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

  active = YES;
  handshake = NO;

  requireVerified = outgoing ? verifyServer : verifyClient;
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
  if ([self _verify] < 0)
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
          [[NSNotificationCenter defaultCenter]
            postNotificationName: GSTLSVerifyFailedNotification
                          object: self];
        }
    }
  else if (globalDebug > 1)
    {
      NSLog(@"%p succeeded verify:\n%@", handle, [self sessionInfo]);
    }
  return YES;
}

- (NSString*) issuer
{
  return issuer;
}

- (NSString*) owner
{
  return owner;
}

- (size_t) pending
{
  GSSChannelState       *st = (GSSChannelState*)state;
  size_t                avail;

  if (NULL == st || NO == active)
    {
      return 0;
    }
  if (st->decOff == [st->decBuf length])
    {
      /* Data already read from the network must be reported, since the
       * caller won't get another readable event for it.
       */
      [self _decrypt];
    }
  avail = [st->decBuf length] - st->decOff;
  if (0 == avail && (st->failed || st->peerClosed))
    {
      avail = 1;        // So that a read picks up the end of file or error
    }
  return avail;
}

- (NSString*) problem
{
  return problem;
}

- (NSInteger) read: (void*)buf length: (NSUInteger)len
{
  GSSChannelState       *st = (GSSChannelState*)state;

  if (NULL == st || NO == active)
    {
      setTLSErrno(EBADF);
      return -1;
    }
  if (0 == len)
    {
      return 0;
    }
  AUTORELEASE(RETAIN(self));    // Callbacks may release us
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
  GSSChannelState       *st = (GSSChannelState*)state;
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
  AUTORELEASE(RETAIN(self));    // Callbacks may release us

  /* As with GNUTLS, when a record could not be sent completely the caller
   * retries with the same data, and we report how much of it the record
   * contained once it has been sent.
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
      ASSIGN(problem, statusString(s));
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
  GSSChannelState               *st = (GSSChannelState*)state;
  NSMutableString               *str;
  SecPkgContext_ConnectionInfo  ci;
  SecPkgContext_CipherInfo      info;
  PCCERT_CONTEXT                remote = NULL;

  str = [NSMutableString stringWithCapacity: 2000];
  if (outgoing)
    {
      [str appendFormat: @"- Outgoing session: %p to '%@'\n",
	self, [opts objectForKey: GSTLSServerName]];
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
      [str appendFormat: @"- Protocol: %@\n", protocolName(ci.dwProtocol)];
    }
  memset(&info, 0, sizeof(info));
  info.dwVersion = SECPKGCONTEXT_CIPHERINFO_V1;
  if (SEC_E_OK == QueryContextAttributesW(&st->ctxt,
    SECPKG_ATTR_CIPHER_INFO, &info))
    {
      [str appendFormat: @"- Cipher suite: %@\n",
        fromWide(info.szCipherSuite)];
      [str appendFormat: @"- Key Exchange: %@\n", fromWide(info.szExchange)];
      [str appendFormat: @"- Cipher: %@\n", fromWide(info.szCipher)];
      [str appendFormat: @"- MAC: %@\n", fromWide(info.szHash)];
    }
  if (SEC_E_OK == QueryContextAttributesW(&st->ctxt,
    SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote) && NULL != remote)
    {
      [str appendString: @"- Peer certificate\n"];
      certInfo(remote, str);
      CertFreeCertificateContext(remote);
    }
  else
    {
      [str appendString: @"- Peer provided no certificate.\n"];
    }
  return str;
}

/* Verifies the remote system's certificate.
 * Returns 0 on success, -1 on failure (with problem set).
 */
- (int) _verify
{
  GSSChannelState       *st = (GSSChannelState*)state;
  PCCERT_CONTEXT        remote = NULL;
  PCCERT_CHAIN_CONTEXT  chain = NULL;
  HCERTSTORE            extra;
  HCERTSTORE            caStore = credentials->caStore;
  CERT_CHAIN_PARA       cp;
  LPSTR                 usage;
  DWORD                 authType;
  DWORD                 err;
  BOOL                  trusted;
  NSMutableString       *ci;
  NSString              *nameList;
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
      ASSIGN(problem, ([NSString stringWithFormat:
        @"TLS verification: error %@", statusString(GetLastError())]));
      goto done;
    }

  err = chainPolicyError(chain, authType, 0, NULL);
  trusted = (0 == err && NO == credentials->exclusive) ? YES : NO;
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
            reason = [NSString stringWithFormat: @", %@", statusString(err)];
            break;
        }
      ASSIGN(problem, ([NSString stringWithFormat:
        @"TLS verification: remote certificate is not trusted%@.", reason]));
      goto done;
    }

  nameList = [opts objectForKey: GSTLSRemoteHosts];
  if (nil == nameList)
    {
      /* If nothing is specified, assume the connection host name
       * (if any) should be used for verification.
       */
      nameList = [opts objectForKey: GSTLSServerName];
      names = ([nameList length] > 0) ? [NSArray arrayWithObject: nameList]
        : nil;
    }
  else
    {
      /* A comma separated list of permitted host names.
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
          ASSIGN(problem, ([NSString stringWithFormat:
            @"TLS verification: hostname does not match '%@' in %@",
            nameList, ci]));
          goto done;
        }
    }

  names = [opts objectForKey: GSTLSIssuers];
  if ([names isKindOfClass: [NSArray class]]
    && (nil == issuer || NO == [names containsObject: issuer]))
    {
      ASSIGN(problem, ([NSString stringWithFormat:
        @"TLS verification: issuer does not match '%@' in %@", names, ci]));
      goto done;
    }

  names = [opts objectForKey: GSTLSOwners];
  if ([names isKindOfClass: [NSArray class]]
    && (nil == owner || NO == [names containsObject: owner]))
    {
      ASSIGN(problem, ([NSString stringWithFormat:
        @"TLS verification: owner does not match '%@' in %@", names, ci]));
      goto done;
    }

  result = 0;

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

#endif  /* HAVE_SCHANNEL */
