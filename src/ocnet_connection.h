#ifndef __ONC_CONNECTION____H__
#define __ONC_CONNECTION____H__

struct onc_connection_s;
typedef struct onc_connection_s onc_connection_s_t;

#ifdef __cplusplus
extern "C" {
#endif

onc_connection_s_t *onc_connection_new(void *evgrp);
int  onc_connection_feed(onc_connection_s_t *onc_conn,
            char *buf, int len);
int  onc_connection_grab(onc_connection_s_t *onc_conn,
            char *buf, int len);
int  onc_connection_eof(onc_connection_s_t *onc_conn);
int  onc_connection_data_available(onc_connection_s_t *onc_conn, void *lfds);
void onc_connection_del(onc_connection_s_t *onc_conn);

#ifdef __cplusplus
}
#endif

#endif
