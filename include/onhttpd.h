#ifndef __ONC_HTTPD____H__
#define __ONC_HTTPD____H__

#include "on_iport.h"

#ifdef __cplusplus
extern "C" {
#endif

int     onc_httpd_init(int internal_evgrp, void *evgrp);
int     onc_httpd_listen(onc_ip_t ip, onc_port_t port);
int     onc_httpd_start(void);
void    onc_httpd_stop(void);
void    onc_httpd_final(void);

#ifdef __cplusplus
}
#endif

#endif
