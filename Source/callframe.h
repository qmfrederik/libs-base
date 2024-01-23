// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: 8f41bfbd73662058764c587fc1bad329e8e3f4a7 
// Date: 2020-06-05 13:56:15 -0400 
// ========== End of Keysight Technologies Notice ========== 
/* callframe - Wrapper/Objective-C interface for ffcall function interface

   Copyright (C) 2000, Free Software Foundation, Inc.
   
   Written by:  Adam Fedor <fedor@gnu.org>
   Created: Nov 2000
   
   This file is part of the GNUstep Base Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110 USA.
   */ 

#ifndef callframe_h_INCLUDE
#define callframe_h_INCLUDE

#include "Foundation/NSMethodSignature.h"
#include "GNUstepBase/DistributedObjects.h"

@class NSInvocation;

typedef struct _callframe_t {
  int nargs;
  void *rtype;
  void **args;
} callframe_t;

extern callframe_t *callframe_from_signature (NSMethodSignature *info,
  void **retval);
extern void callframe_set_arg(callframe_t *cframe, int index, void *buffer,
			      int size);
extern void callframe_get_arg(callframe_t *cframe, int index, void *buffer,
			      int size);
extern void *callframe_arg_addr(callframe_t *cframe, int index);

#endif

