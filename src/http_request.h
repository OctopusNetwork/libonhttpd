#ifndef __ONC_HTTP_REQUEST____H__
#define __ONC_HTTP_REQUEST____H__

struct onc_httpreq_s;
typedef struct onc_httpreq_s   onc_httpreq_s_t;

#ifdef __cplusplus
extern "C" {
#endif

onc_httpreq_s_t *http_request_new(void);
void http_request_del(onc_httpreq_s_t *request);
int http_request_parse(onc_httpreq_s_t *request,
        const char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif
