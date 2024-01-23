// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
// Date: 2015-07-07 22:31:41 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "ObjectTesting.h"
#import <Foundation/Foundation.h>

id a,b,c;

int main(void)
{
  NSAutoreleasePool     *p = [NSAutoreleasePool new];
  NSFileHandle  *a;
  NSFileHandle  *b;
  NSFileHandle  *c;

  START_SET("handle creation")
  a = [NSFileHandle fileHandleWithStandardInput];
  b = [NSFileHandle fileHandleWithStandardOutput];
  c = [NSFileHandle fileHandleWithStandardError];
  END_SET("handle creation")
  PASS([a retainCount]> 0, "stdin persists");
  PASS([b retainCount]> 0, "stdout persists");
  PASS([c retainCount]> 0, "strerr persists");
  PASS_EXCEPTION([a release], NSGenericException, "Cannot dealloc stdin");
  PASS_EXCEPTION([b release], NSGenericException, "Cannot dealloc stdout");
  PASS_EXCEPTION([c release], NSGenericException, "Cannot dealloc stderr");
  PASS([a retainCount]> 0, "stdin persists");
  PASS([b retainCount]> 0, "stdout persists");
  PASS([c retainCount]> 0, "strerr persists");

  [p drain];
  return 0;
}
