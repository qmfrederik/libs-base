// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
// Date: 2015-07-07 22:31:41 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "Testing.h"
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSObject.h>
#import <Foundation/NSString.h>

/* Only do associated objects test if they are supported by the runtime.
 */
#if     OBJC2RUNTIME && defined(OBJC_ASSOCIATION_RETAIN)

static BOOL AssociatedObjectDeallocCalled = NO;
static const char* objc_setAssociatedObjectKey = "objc_setAssociatedObjectKey";

@interface associatedObjectTestAssociatedObject : NSObject
@end

@implementation associatedObjectTestAssociatedObject

- (void) dealloc
{
  AssociatedObjectDeallocCalled = YES;
  [super dealloc];
}

@end

@interface associatedObjectTestAllocatedObject : NSObject
@end

@implementation associatedObjectTestAllocatedObject
@end

int main()
{
  associatedObjectTestAllocatedObject* object = 
  	[associatedObjectTestAllocatedObject new];

  associatedObjectTestAssociatedObject *info = 
  	[associatedObjectTestAssociatedObject new];
  objc_setAssociatedObject(object, &objc_setAssociatedObjectKey, info, 
	OBJC_ASSOCIATION_RETAIN);
  [info release];
  [object release];

  PASS(AssociatedObjectDeallocCalled == YES, 
       "'objc_setAssociatedObject' was released");
  return 0;
}

#else

int main()
{
  return 0;     // Nothing to test
}

#endif
