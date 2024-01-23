// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "ObjectTesting.h"
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSArray.h>

int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  NSArray *testObj = [NSMutableArray arrayWithCapacity:1];
  test_alloc(@"NSMutableArray");
  test_NSObject(@"NSMutableArray", [NSArray arrayWithObject:testObj]); 
  test_NSCoding([NSArray arrayWithObject:testObj]); 
  test_keyed_NSCoding([NSArray arrayWithObject:testObj]); 
  test_NSCopying(@"NSArray",@"NSMutableArray", 
                 [NSArray arrayWithObject:testObj], NO, NO); 
  test_NSMutableCopying(@"NSArray",@"NSMutableArray", 
                 [NSArray arrayWithObject:testObj]); 

NSMutableString *str1, *str2;
 unichar chars[3];

 chars[0] = '\"';
 chars[1] = 1;
 str1 = [NSMutableString stringWithCharacters: chars length: 2];
 [str1 replaceOccurrencesOfString: @"\""
                      withString: @"\\\""
                         options: 0
                           range: NSMakeRange(0, [str1 length])];

 chars[0] = '\\';
 chars[1] = '\"';
 chars[2] = 1;
 str2 = [NSMutableString stringWithCharacters: chars length: 3];
 NSLog(@"string 1 %@ string 2 %@", str1, str2);
 PASS([str1 isEqual: str2],
   "string occurrences replacement works");
  [arp release]; arp = nil;
  return 0;
}
