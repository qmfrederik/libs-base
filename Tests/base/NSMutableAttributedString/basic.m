// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSAttributedString.h>
#import "ObjectTesting.h"
int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  NSArray *arr = [NSArray arrayWithObject:[NSMutableAttributedString new]];
  
  test_alloc(@"NSMutableAttributedString");
  test_NSObject(@"NSMutableAttributedString", arr);
  test_NSCoding(arr);
  test_keyed_NSCoding(arr);
  test_NSCopying(@"NSAttributedString",@"NSMutableAttributedString",arr,NO, NO);
  test_NSMutableCopying(@"NSAttributedString",@"NSMutableAttributedString",arr);

  [arp release]; arp = nil;
  return 0;
}

