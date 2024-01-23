// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 

#include "objc-common.g"

GS_OBJC_ROOT_CLASS @interface Test 
+(int) testResult;
@end

@implementation Test
+ (void) initialize
{
  return;
}
+(int) testResult
{
  return -1;
}
@end

int main (void)
{
  return ([Test testResult] + 1);
}
