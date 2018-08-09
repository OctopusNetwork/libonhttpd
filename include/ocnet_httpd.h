#ifndef __ONC_HTTPD____H__
#define __ONC_HTTPD____H__

#include "ocnet_iport.h"

#ifdef __cplusplus
extern "C" {
#endif

int     ocnet_httpd_init(int internal_evgrp, void *evgrp);
int     ocnet_httpd_listen(ocnet_ip_t ip, ocnet_port_t port);
int     ocnet_httpd_start(void);
void    ocnet_httpd_stop(void);
void    ocnet_httpd_final(void);

#ifdef __cplusplus
}
#endif

#endif
