#ifndef __ONC_CONNECTION____H__
#define __ONC_CONNECTION____H__

struct ocnet_connection;
typedef struct ocnet_connection ocnet_connection_t;

#ifdef __cplusplus
extern "C" {
#endif

ocnet_connection_t *ocnet_connection_new(void *evgrp);
int  ocnet_connection_feed(ocnet_connection_t *ocnet_conn,
            char *buf, int len);
int  ocnet_connection_grab(ocnet_connection_t *ocnet_conn,
            char *buf, int len);
int  ocnet_connection_eof(ocnet_connection_t *ocnet_conn);
int  ocnet_connection_data_available(ocnet_connection_t *ocnet_conn, void *lfds);
void ocnet_connection_del(ocnet_connection_t *ocnet_conn);

#ifdef __cplusplus
}
#endif

#endif
