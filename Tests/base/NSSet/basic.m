// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "ObjectTesting.h"
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSSet.h>

int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  NSSet *testObj;
  NSMutableArray *testObjs = [NSMutableArray new];

  testObj = [NSSet new];
  [testObjs addObject:testObj];
  PASS(testObj != nil && [testObj count] == 0,
       "can create an empty set");
   
  testObj = [NSSet setWithObject:@"Hello"];
  [testObjs addObject:testObj];
  PASS(testObj != nil && [testObj count] == 1, "can create a set with one element");
  
  test_NSObject(@"NSSet", testObjs);
  test_NSCoding(testObjs);
  test_keyed_NSCoding(testObjs);
  test_NSCopying(@"NSSet", @"NSMutableSet", testObjs, YES, NO);
  test_NSMutableCopying(@"NSSet", @"NSMutableSet", testObjs);
  

  [arp release]; arp = nil;
  return 0;
}
