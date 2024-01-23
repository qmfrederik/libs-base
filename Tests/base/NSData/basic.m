// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "ObjectTesting.h"
#import <Foundation/NSData.h>
#import <Foundation/NSAutoreleasePool.h>

int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  id testObject = [NSData new];
  test_alloc(@"NSData");
  test_NSObject(@"NSData",[NSArray arrayWithObject:testObject]);
  test_NSCoding([NSArray arrayWithObject:testObject]);
  test_keyed_NSCoding([NSArray arrayWithObject:testObject]);
  test_NSCopying(@"NSData",
                 @"NSMutableData",
		 [NSArray arrayWithObject:testObject], NO, NO);
  test_NSMutableCopying(@"NSData",
                        @"NSMutableData",
		        [NSArray arrayWithObject:testObject]);

  [arp release]; arp = nil;
  return 0;
}

