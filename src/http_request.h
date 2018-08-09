#ifndef __ONC_HTTP_REQUEST____H__
#define __ONC_HTTP_REQUEST____H__

struct ocnet_httpreq;
typedef struct ocnet_httpreq   ocnet_httpreq_t;

#ifdef __cplusplus
extern "C" {
#endif

ocnet_httpreq_t *http_request_new(void);
void http_request_del(ocnet_httpreq_t *request);
int http_request_parse(ocnet_httpreq_t *request,
        const char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif
