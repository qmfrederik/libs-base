// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import <Foundation/NSNotification.h>
#import <Foundation/NSAutoreleasePool.h>
#import "ObjectTesting.h"

@implementation NSNotification (Testing)
- (BOOL) isEqualForTestcase: (id)other
{
  if (NO == [other isKindOfClass: [NSNotification class]])
    return NO;
  if ([self name] != [other name]
    && NO == [[self name] isEqual: [other name]])
    return NO;
  if ([self object] != [other object]
    && NO == [[self object] isEqual: [other object]])
    return NO;
  if ([self userInfo] != [other userInfo]
    && NO == [[self userInfo] isEqual: [other userInfo]])
    return NO;
  return YES;
}
@end

int main()
{
  NSNotification *obj;
  NSMutableArray *testObjs = [[NSMutableArray alloc] init];
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];

  test_alloc(@"NSNotification"); 
  obj = [NSNotification new];
  [testObjs addObject: obj];
  test_NSObject(@"NSNotification", testObjs);
  test_NSCoding(testObjs);
  test_keyed_NSCoding(testObjs);
  test_NSCopying(@"NSNotification",@"NSNotification",testObjs,NO,NO);
  
  [arp release]; arp = nil;
  return 0;
}
