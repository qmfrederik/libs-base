// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
// Date: 2015-07-07 22:31:41 +0000 
// ========== End of Keysight Technologies Notice ========== 
#include "ObjectiveC2/objc/capabilities.h"

/**
 * Bitmask of all of the capabilities compiled into this version of the
 * runtime.
 */
static const int caps = 0
  | (1 << OBJC_CAP_EXCEPTIONS)
  | (1 << OBJC_CAP_SYNCRONIZE)
  | (1 << OBJC_CAP_PROPERTIES);

int objc_test_capability(int x)
{
  if (x >= 32)
    {
      return 0;
    }
  if (caps & (1 << x))
    {
      return 1;
    }
  return 0;
}
