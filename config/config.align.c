// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: 01b13228d3ecfd3d555d73daf1c448ad809970a9 
// Date: 2016-09-13 20:15:05 +0000 
// ========== End of Keysight Technologies Notice ========== 
/* This program will most likely crash on systems that need shorts and ints
   to be word aligned
  Copyright (C) 2005 Free Software Foundation

  Copying and distribution of this file, with or without modification,
  are permitted in any medium without royalty provided the copyright
  notice and this notice are preserved.

*/
#include <stdlib.h>

int main ()
{
  char  *buf = malloc(30);
  void  *v;
  short *sp;
  short *sq;
  int   *ip;
  int   *iq;
  int   i;

  for (i = 0 ; i < 30; i++)
    {
      buf[i] = i;
    }
  v = buf;

  sp = (short*)(v + 1);
  sq = (short*)(v + 2);
  if (*sp == *sq)
    {
      return 1;
    }

  ip = (int*)(v + 1);
  iq = (int*)(v + 2);
  if (*ip == *iq)
    {
      return 1;
    }

  return 0;
}

