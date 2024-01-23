// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d6bb85721e7e7b111ef2505fd7df37d2d1887355 
// Date: 2016-09-13 21:55:49 +0000 
// ========== End of Keysight Technologies Notice ========== 

#ifdef __clang__
#define FOR_IN(type, var, collection) \
  for (type var in collection)\
  {
#define END_FOR_IN(collection) }
#else
void objc_enumerationMutation(id);
#define FOR_IN(type, var, c) \
do\
{\
  type var;\
  NSFastEnumerationState gs_##c##_enumState = { 0 };\
  id gs_##c##_items[16];\
  unsigned long gs_##c##_limit = \
    [c countByEnumeratingWithState: &gs_##c##_enumState \
                           objects: gs_##c##_items \
                             count: 16];\
  if (gs_##c##_limit)\
  {\
    unsigned long gs_startMutations = *gs_##c##_enumState.mutationsPtr;\
    do {\
      unsigned long gs_##c##counter = 0;\
      do {\
        if (gs_startMutations != *gs_##c##_enumState.mutationsPtr)\
        {\
          objc_enumerationMutation(c);\
        }\
        var = gs_##c##_enumState.itemsPtr[gs_##c##counter++];\

#define END_FOR_IN(c) \
      } while (gs_##c##counter < gs_##c##_limit);\
    } while ((gs_##c##_limit \
      = [c countByEnumeratingWithState: &gs_##c##_enumState\
			       objects: gs_##c##_items\
				 count: 16]));\
  }\
} while(0);
#endif
