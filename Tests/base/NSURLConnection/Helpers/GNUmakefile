# ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
# Committed by: Marcian Lytwyn 
# Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
# Date: 2015-07-07 22:31:41 +0000 
# ========== End of Keysight Technologies Notice ========== 
include $(GNUSTEP_MAKEFILES)/common.make

BUNDLE_NAME = TestConnection

TestConnection_OBJC_FILES = TestCase.m SimpleWebServer.m TestWebServer.m NSURLConnectionTest.m RequestHandler.m
#TestConnection_OBJC_LIBS += -lWebServer -lPerformance
TestConnection_RESOURCE_FILES += testKey.pem testCert.pem
TestConnection_PRINCIPAL_CLASS = NSURLConnectionTest

StatusServer_NEEDS_GUI = NO

TOOL_NAME = testTestWebServer
testTestWebServer_OBJC_FILES += testTestWebServer.m
testTestWebServer_NEEDS_GUI = NO

-include GNUmakefile.preamble
include $(GNUSTEP_MAKEFILES)/bundle.make
include $(GNUSTEP_MAKEFILES)/tool.make
-include GNUmakefile.postamble

