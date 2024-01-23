// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "ObjectTesting.h"
#import <Foundation/Foundation.h>
#import <Foundation/NSStream.h>

int main()
{
  NSAutoreleasePool   *arp = [NSAutoreleasePool new];
  NSInputStream *t1;
  NSOutputStream *t2;
  NSArray *a;
  NSHost *host = [NSHost hostWithName:@"localhost"];

  [NSStream getStreamsToHost:host port:80 inputStream:&t1 outputStream:&t2];

  a = [NSArray arrayWithObjects:t1, t2, nil]; 
  test_NSObject(@"NSStream", a); 

  [arp release]; arp = nil;
  return 0;
}
