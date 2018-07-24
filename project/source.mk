COMMON_INCLUDE_DIRS += $(rootdir)/$(MODULE)/include             \
                       $(incdir)/libonutils                       \
                       $(incdir)/libontcpeng                      \
                       $(incdir)/libonevent                       \
                       $(incdir)/liboncommunication                  \
                       $(incdir)/libonhttp_parser                    \
                       $(incdir)/libonlog                         \
                       $(incdir)/libonplatform

COMMON_SRC_FILES := $(rootdir)/$(MODULE)/src/on_httpd.c        \
                    $(rootdir)/$(MODULE)/src/http_request.c     \
                    $(rootdir)/$(MODULE)/src/on_connection.c   \
                    $(rootdir)/$(MODULE)/src/on_parser.c

COMMON_INST_HEADER_DIRS += $(rootdir)/$(MODULE)/include
