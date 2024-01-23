# ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
# Committed by: Frank Le Grand 
# Commit ID: 5d77e1e33ac61e7f44ee32860a83fefff83d62c8 
# Date: 2013-08-09 14:20:01 +0000 
# ========== End of Keysight Technologies Notice ========== 

include $(GNUSTEP_MAKEFILES)/common.make

BUNDLE_NAME = TestBundle

TestBundle_OBJC_FILES = TestBundle.m
TestBundle_RESOURCE_FILES = NonLocalRes.txt
TestBundle_LANGUAGES = English French de
TestBundle_LOCALIZED_RESOURCE_FILES = TextRes.txt
TestBundle_NEEDS_GUI = NO

include $(GNUSTEP_MAKEFILES)/bundle.make

check::	all
