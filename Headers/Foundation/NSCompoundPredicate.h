// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Frank Le Grand 
// Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
// Date: 2013-08-09 14:20:01 +0000 
// ========== End of Keysight Technologies Notice ========== 
/* Interface for NSCompoundPredicate for GNUStep
   Copyright (C) 2005 Free Software Foundation, Inc.

   Written by:  Dr. H. Nikolaus Schaller
   Created: 2005
   
   This file is part of the GNUstep Base Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02111 USA.
   */ 

#ifndef __NSCompoundPredicate_h_GNUSTEP_BASE_INCLUDE
#define __NSCompoundPredicate_h_GNUSTEP_BASE_INCLUDE
#import	<GNUstepBase/GSVersionMacros.h>

#if	OS_API_VERSION(MAC_OS_X_VERSION_10_4, GS_API_LATEST)

#import	<Foundation/NSPredicate.h>

#if	defined(__cplusplus)
extern "C" {
#endif

enum
{
  NSNotPredicateType = 0,
  NSAndPredicateType,
  NSOrPredicateType
};
typedef NSUInteger NSCompoundPredicateType;

GS_EXPORT_CLASS @interface NSCompoundPredicate : NSPredicate
{
#if	GS_EXPOSE(NSCompoundPredicate)
  NSCompoundPredicateType _type;
  NSArray	*_subs;
#endif
}

+ (NSPredicate *) andPredicateWithSubpredicates: (NSArray *)list;
+ (NSPredicate *) notPredicateWithSubpredicate: (NSPredicate *)predicate;
+ (NSPredicate *) orPredicateWithSubpredicates: (NSArray *)list;

- (NSCompoundPredicateType) compoundPredicateType;
- (id) initWithType: (NSCompoundPredicateType)type
      subpredicates: (NSArray *)list;
- (NSArray *) subpredicates;

@end

#if	defined(__cplusplus)
}
#endif

#endif	/* 100400 */
#endif

