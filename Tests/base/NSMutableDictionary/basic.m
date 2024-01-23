// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "ObjectTesting.h"
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSDictionary.h>

int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  NSMutableDictionary *testObj;
  
  testObj = [NSMutableDictionary new];
  
  test_NSObject(@"NSMutableDictionary", [NSArray arrayWithObject:testObj]);
  
  test_NSCoding([NSArray arrayWithObject:testObj]);

  test_keyed_NSCoding([NSArray arrayWithObject:testObj]);
  
  test_NSCopying(@"NSDictionary",@"NSMutableDictionary", 
                 [NSArray arrayWithObject:testObj], NO, NO);
  
  test_NSMutableCopying(@"NSDictionary",@"NSMutableDictionary", 
                        [NSArray arrayWithObject:testObj]);
  [arp release]; arp = nil;
  return 0;
}
