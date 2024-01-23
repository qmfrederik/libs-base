// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
// Date: 2015-07-07 22:31:41 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import <Foundation/Foundation.h>
#import "Testing.h"

static int      called = 0;

@interface NSMessageTest : NSObject
@end

@implementation NSMessageTest

- (void) methodToCall
{
  called++;
}

@end



int main(void)
{
  NSAutoreleasePool* pool = [NSAutoreleasePool new];
  NSMessageTest* test = [NSMessageTest new];

  [NS_MESSAGE(test, methodToCall) invoke];

  PASS(called > 0, "NS_MESSAGE worked");

  [pool release];
  return 0;
}



