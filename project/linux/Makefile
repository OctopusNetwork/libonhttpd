rootdir := $(shell pwd)/../../..
project := ubuntu-base

include $(rootdir)/build/common/inc.mk
ifeq ($(hostmaketype), windows)
rootdir := ../../..
endif

TARGETSPEC = libonhttpd
TARGET_LIB = libonhttpd.$(staticlibsuffix)

DEP_ARCHIVES = liboncommunication

MODULE = libonhttpd
MODULEVERSION = 0.0.1

include ../source.mk
include $(rootdir)/build/utils/merged-archive.$(hostmaketype).mk
