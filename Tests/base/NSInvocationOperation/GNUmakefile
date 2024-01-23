# ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
# Committed by: Frank Le Grand 
# Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
# Date: 2013-08-09 14:20:01 +0000 
# ========== End of Keysight Technologies Notice ========== 
# __GENERATED__ makefile marker
#

include $(GNUSTEP_MAKEFILES)/common.make
-include ../GNUmakefile.super

GNUSTEP_OBJ_DIR=./obj

TEST_TOOL_NAME =  basic

ifeq ($(gcov),yes)
ADDITIONAL_OBJCFLAGS += -ftest-coverage -fprofile-arcs
ADDITIONAL_OBJCCFLAGS += -ftest-coverage -fprofile-arcs
ADDITIONAL_LDFLAGS += -ftest-coverage -fprofile-arcs
ADDITIONAL_TOOL_LIBS+=-lgcov
endif


basic_OBJC_FILES=basic.m

-include GNUmakefile.preamble
include $(GNUSTEP_MAKEFILES)/test-tool.make
-include GNUmakefile.postamble

after-clean::
	rm -f core tests.log tests.sum oldtests.log oldtests.sum

