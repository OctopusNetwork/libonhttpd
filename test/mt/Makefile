rootdir := $(shell pwd)/../../..
project := ubuntu-base

include $(rootdir)/build/common/inc.mk
ifeq ($(hostmaketype), windows)
rootdir := ../../..
endif

####
##  Application targets
####
DEP_HEADERS += $(incdir)/kkthttpd $(incdir)/libonplatform

apps = mt_httpd

mt_httpd_SRCS = $(rootdir)/libonhttpd/test/mt/httpd_main.c
mt_httpd_ARCHIVES = libontcpeng libonplatform libonevent liboncommunication libonhttpd   \
                    libonhttp_parser libonlog
mt_httpd_LDLIBS = -pthread
mt_httpd_DISTSOLIBS =

include $(rootdir)/build/utils/app.mk
