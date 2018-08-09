rootdir := $(shell pwd)/../../../..
project := ubuntu-base

include $(rootdir)/build/project/$(project).mk
include $(rootdir)/build/common/common.mk

####
##  Application targets
####
DEP_HEADERS += $(incdir)/libonhttpd $(incdir)/libonplatform

apps = mt_httpd

mt_httpd_SRCS = $(sourcedir)/libonhttpd/test/mt/httpd_main.c
mt_httpd_ARCHIVES = ontcpeng onplatform onevent oncommunication onhttpd   \
                    http_parser onlogger
mt_httpd_LDLIBS = -pthread
mt_httpd_DISTSOLIBS =

include $(rootdir)/build/utils/app.mk
