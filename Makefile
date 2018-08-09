rootdir := $(shell pwd)/../..
project ?= ubuntu-base

include $(rootdir)/build/project/$(project).mk
include $(rootdir)/build/common/common.mk

TARGET_ARCHIVE = libonhttpd.a
MODULENAME = libonhttpd
MODULEVERSION = 0.1.0

COMMON_INCLUDE_DIRS += $(rootdir)/source/$(MODULENAME)/include              \
                       $(incdir)/libonplatform $(incdir)/libonevent         \
                       $(incdir)/liboncommunication $(incdir)/libontcpeng   \
                       $(incdir)/libonutils
COMMON_SRC_FILES := $(rootdir)/source/$(MODULENAME)/src/ocnet_connection.c          \
                    $(rootdir)/source/$(MODULENAME)/src/ocnet_httpd.c               \
                    $(rootdir)/source/$(MODULENAME)/src/ocnet_parser.c              \
                    $(rootdir)/source/$(MODULENAME)/src/http_request.c
COMMON_INST_HEADER_DIRS += $(rootdir)/source/$(MODULENAME)/include

include $(rootdir)/build/utils/archive.mk

.PHONY : sync
