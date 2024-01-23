// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
#import "Testing.h"
#import <Foundation/NSAutoreleasePool.h>
#import <Foundation/NSPathUtilities.h>
#import <Foundation/NSString.h>

int main()
{
  START_SET("tilde")
  NSString      *home = NSHomeDirectory();
  NSString      *tmp;

  PASS_EQUAL([home stringByAbbreviatingWithTildeInPath], @"~",
   "home directory becomes tilde");

  tmp = [home stringByAppendingPathComponent: @"Documents"];
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], @"~/Documents",
    "the Documents subdirectory becomes ~/Documents");
  
  tmp = [home stringByAppendingString: @"/Documents"];
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], @"~/Documents",
    "trailing slash removed");

  tmp = [home stringByAppendingString: @"//Documents///"];
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], @"~/Documents",
    "multiple slashes removed");

  tmp = [home stringByAppendingString: @"/Documents//.."];
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], @"~/Documents/..",
    "upper directory reference retained");

  tmp = [home stringByAppendingString: @"/Documents/./.."];
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], @"~/Documents/./..",
    "dot directory reference retained");

  tmp = [NSString stringWithFormat: @"////%@//Documents///", home];
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], @"~/Documents",
    "multiple slashes removed");

  PASS_EQUAL([@"//////Documents///" stringByAbbreviatingWithTildeInPath],
    @"/Documents",
    "multiple slashes removed without tilde replacement");

  PASS_EQUAL([@".//////Documents///" stringByAbbreviatingWithTildeInPath],
    @"./Documents",
    "multiple slashes removed without tilde replacement");

  END_SET("tilde")

  START_SET("tilde abbreviation for other home")
  NSString      *home = NSHomeDirectory();
  NSString      *tmp;

  /* The idea here is to use a home directory for a user other than the
   * current one.  We pick root as a user which will exist on most systems.
   * If the current user is root then this will not work, so we skip the
   * test in that case.
   */
  tmp  = NSHomeDirectoryForUser(@"root");
  if (0 == [tmp length])
    {
      SKIP("can't determine root's home directory for tilde test")
    }
  if (YES == [tmp isEqual: home])
    {
      SKIP("home directory of current user is root's home")
    }
  PASS_EQUAL([tmp stringByAbbreviatingWithTildeInPath], tmp,
    "tilde does nothing for root's home");

  END_SET("tilde abbreviation for other home")
  return 0;
}
