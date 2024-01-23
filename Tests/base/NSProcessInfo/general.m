// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
// Date: 2015-07-07 22:31:41 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "Testing.h"
#import <Foundation/NSArray.h>
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSProcessInfo.h>
#import <Foundation/NSString.h>

int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  NSProcessInfo *info = [NSProcessInfo processInfo];
  id obj;
  unsigned int val;
  PASS(info != nil, "NSProcessInfo understands [+processInfo]");
  
  obj = [info arguments];
  PASS((info != nil && 
       [obj isKindOfClass:[NSArray class]] &&
       [obj count] != 0),
       "NSProcessInfo has arguments");
  
  obj = [info environment];
  PASS((obj != nil &&
       [obj isKindOfClass:[NSDictionary class]]), 
       "NSProcessInfo has environment");
  
  obj = [info processName]; 
  PASS((obj != nil &&
       [obj isKindOfClass:[NSString class]] &&
       [obj length] > 0),
       "-processName is non-nil");

  obj = [info globallyUniqueString];
  PASS((obj != nil &&
       [obj isKindOfClass:[NSString class]] &&
       [obj length] > 0),
       "-globallyUniqueString works");

  obj = [info operatingSystemName];
  PASS((obj != nil && [obj isKindOfClass:[NSString class]] && [obj length] > 0),
       "-operatingSystemName works");
  NSLog(@"operatingSystemName %@", obj);
  val = [info operatingSystem];
  PASS(val != 0, "-operatingSystem works"); 
  obj = [info hostName];
  PASS((obj != nil && [obj isKindOfClass:[NSString class]] && [obj length] > 0),
    "-hostName works"); 
  NSLog(@"hostName %@", obj);
  [arp release]; arp = nil;
  return 0;
}
