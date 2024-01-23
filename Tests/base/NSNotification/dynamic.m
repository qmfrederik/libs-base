// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#import "ObjectTesting.h"

static BOOL notifiedCurrent = NO;

@interface Toggle : NSObject
@end

@implementation Toggle
- (void) foo: (NSNotification*)n
{
  notifiedCurrent = NO;
}
- (void) bar: (NSNotification*)n
{
  notifiedCurrent = YES;
}
@end

int main(void)
{
  NSNotificationCenter *nc;
  id t = [Toggle new];

  [NSAutoreleasePool new];
  nc = [NSNotificationCenter new];
  [nc addObserver: t selector: @selector(foo:) name: nil object: nil];
  class_replaceMethod([Toggle class],
    @selector(foo:),
    class_getMethodImplementation([Toggle class], @selector(bar:)),
    "v@:@");
  [nc postNotificationName: @"foo" object: t];
  [t release];
  PASS(YES == notifiedCurrent, "implementation not cached");
  return 0;
}
