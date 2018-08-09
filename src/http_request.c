#include <stdint.h>

#include "ocnet_malloc.h"

#include "http_request.h"
#include "ocnet_parser.h"

typedef struct ocnet_httpreq {
    ocnet_parser_t *ocnet_parser;
} ocnet_httpreq_t;

ocnet_httpreq_t *http_request_new(void)
{
    ocnet_httpreq_t *request = NULL;
    ocnet_parser_cb_t callbacks;

    request = ocnet_malloc(sizeof(ocnet_httpreq_t));
    if (NULL == request) {
        return NULL;
    }

    request->ocnet_parser = ocnet_parser_new(&callbacks);
    if (NULL == request->ocnet_parser) {
        goto L_ERROR_KKTPARSER_NEW;
    }

    return request;

L_ERROR_KKTPARSER_NEW:
    ocnet_free(request);
    return NULL;
}

void http_request_del(ocnet_httpreq_t *request)
{
    ocnet_parser_del(request->ocnet_parser);
    ocnet_free(request);
}

int http_request_parse(ocnet_httpreq_t *request,
        const char *buf, int len)
{
    return ocnet_parser_parse(request->ocnet_parser, (char *)buf, len);
}
