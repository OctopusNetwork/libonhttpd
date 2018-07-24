#include <stdint.h>

#include "on_malloc.h"

#include "http_request.h"
#include "on_parser.h"

typedef struct onc_httpreq_s {
    onc_parser_s_t *onc_parser;
} onc_httpreq_s_t;

onc_httpreq_s_t *http_request_new(void)
{
    onc_httpreq_s_t *request = NULL;
    onc_parser_cb_s_t callbacks;

    request = onc_malloc(sizeof(onc_httpreq_s_t));
    if (NULL == request) {
        return NULL;
    }

    request->onc_parser = onc_parser_new(&callbacks);
    if (NULL == request->onc_parser) {
        goto L_ERROR_KKTPARSER_NEW;
    }

    return request;

L_ERROR_KKTPARSER_NEW:
    onc_free(request);
    return NULL;
}

void http_request_del(onc_httpreq_s_t *request)
{
    onc_parser_del(request->onc_parser);
    onc_free(request);
}

int http_request_parse(onc_httpreq_s_t *request,
        const char *buf, int len)
{
    return onc_parser_parse(request->onc_parser, (char *)buf, len);
}
