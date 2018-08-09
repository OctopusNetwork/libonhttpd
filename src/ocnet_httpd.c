#include "ocnet_malloc.h"
#include "ocnet_thread.h"

#include "libonlogger/logger.h"

#include "list.h"

#include "onlfds.h"
#include "onevgrp.h"

#include "tcp_connection.h"
#include "tcp_server.h"

#include "ocnet_httpd.h"

#include "ocnet_connection.h"

#define ONC_HTTPD_MAX_CONNS     128
#define ONC_SERVER_MAX_CONNS    32
#define ONC_EVENT_TIMEOUT       500
#define ONC_WRITE_BUFLEN        (1024 * 1024)

#define TAG     "httpd"

typedef struct {
    void               *tcp_conn;
    void               *http_request;
    ocnet_connection_t *ocnet_conn;
    char               *wbuf;
    char               *swapbuf;
    char                datalen;
    struct list_head    link;
} ocnet_conncon_t;

typedef struct {
    void               *listener;
    struct list_head    link;
} ocnet_httpserver_s_t;

typedef struct {
    unsigned int        internal_evgrp: 1,
                        running:        1;
    struct list_head    listener_list;
    void               *conn_mutex;
    struct list_head    conn_list;
    void               *evgrp;
    int                 msgbuf_pid;
    void               *acceptor;
    void               *processor;
} ocnet_httpd_s_t;

static ocnet_httpd_s_t    g_httpd;

static int __on_read(ocnet_conncon_t *conn, void *lfds)
{
    void *tcp_conn = conn->tcp_conn;
    if (0 != tcp_connection_readable(tcp_conn, lfds)) {
        char buf[1024] = {0};
        int readlen = tcp_connection_read(tcp_conn, buf, sizeof(buf));
        if (0 < readlen) {
            ocnet_connection_feed(conn->ocnet_conn, buf, readlen);
        } else if (readlen < 0) {
            return -1;
        }
    }
    return 0;
}

static int __on_error(ocnet_conncon_t *conn, void *lfds)
{
    void *tcp_conn = conn->tcp_conn;
    return tcp_connection_error(tcp_conn, lfds);
}

static int __on_write(ocnet_conncon_t *conn, void *lfds)
{
    void *tcp_conn = conn->tcp_conn;
    ocnet_connection_t *ocnet_conn = conn->ocnet_conn;

    if (0 == ocnet_connection_eof(ocnet_conn)) {
        if (0 != tcp_connection_writable(tcp_conn, lfds) ||
                0 != ocnet_connection_data_available(ocnet_conn, lfds)) {
            int writelen = 0;
            int buflen = sizeof(conn->wbuf) - conn->datalen;
            int grablen = ocnet_connection_grab(
                    ocnet_conn, conn->wbuf + conn->datalen, buflen);

            /**
             *  If buf is fill, maybe more data available
             *  then we need to wait to write
             *  Otherwise, we only wait to write when write fail
             */
            if (buflen <= grablen) {
                tcp_connection_wait_writable(conn->tcp_conn);
            } else {
                tcp_connection_dontwait_writable(conn->tcp_conn);
            }

            conn->datalen += grablen;
            if (0 < conn->datalen) {
                writelen = tcp_connection_write(
                        tcp_conn, conn->wbuf, conn->datalen);

                if (0 < writelen) {
                    int datalen = conn->datalen;
                    conn->datalen -= writelen;
                    if (writelen < datalen) {
                        ocnet_memcpy(conn->swapbuf, conn->wbuf + writelen,
                                conn->datalen);
                        ocnet_memcpy(conn->wbuf, conn->swapbuf, conn->datalen);
                        tcp_connection_wait_writable(conn->tcp_conn);
                    }
                } else if (writelen < 0) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

static void __destroy_connection(
        ocnet_httpd_s_t *httpd, ocnet_conncon_t *conn)
{
    ocnet_free(conn->swapbuf);
    ocnet_free(conn->wbuf);
    ocnet_connection_del(conn->ocnet_conn);
    ocnet_mutex_lock(httpd->conn_mutex);
    list_del(&conn->link);
    if (1 == httpd->internal_evgrp) {
        tcp_connection_event_del(conn->tcp_conn, httpd->evgrp);
    }
    ocnet_mutex_unlock(httpd->conn_mutex);
    tcp_connection_del(conn->tcp_conn);
    ocnet_free(conn);
}

static int __on_event(ocnet_httpd_s_t *httpd, void *lfds)
{
    ocnet_conncon_t *conn = NULL;
    ocnet_conncon_t *p = NULL;

    list_for_each_entry_safe(conn, p, &httpd->conn_list, link) {
        if (__on_read(conn, lfds) < 0) {
            __destroy_connection(httpd, conn);
            LOGE(TAG, "read error");
            continue;
        }

        if (__on_write(conn, lfds) < 0) {
            __destroy_connection(httpd, conn);
            LOGE(TAG, "write error");
            continue;
        }

        if (1 == __on_error(conn, lfds)) {
            __destroy_connection(httpd, conn);
            LOGE(TAG, "event error");
            continue;
        }
    }

    return 0;
}

static void *__processor(void *arg)
{
    ocnet_httpd_s_t *httpd = (ocnet_httpd_s_t *)arg;
    void *lfds = ocnet_lfds_new();

    if (NULL == lfds) {
        return NULL;
    }

    do {
        int rc = 0;
        rc = ocnet_evgrp_wait(httpd->evgrp, ONC_EVENT_TIMEOUT, lfds);
        if (rc < 0) {
            LOGI(TAG, "event wait error");
        } else if (0 < rc) {
            __on_event(httpd, lfds);
        } else {
            LOGI(TAG, "event wait timeout");
        }
    } while (1 == httpd->running);

    ocnet_lfds_del(lfds);

    return NULL;
}

static ocnet_conncon_t *__create_connection(
        ocnet_httpd_s_t *httpd, void *tcp_conn)
{
    ocnet_connection_t *ocnet_conn = NULL;
    ocnet_conncon_t *conncon = NULL;

    conncon = ocnet_malloc(sizeof(ocnet_conncon_t));
    if (NULL == conncon) {
        return NULL;
    }

    conncon->wbuf = ocnet_malloc(ONC_WRITE_BUFLEN);
    if (NULL == conncon->wbuf) {
        goto L_ERROR_WBUF_ALLOC;
    }

    conncon->swapbuf = ocnet_malloc(ONC_WRITE_BUFLEN);
    if (NULL == conncon->swapbuf) {
        goto L_ERROR_SWAPBUF_ALLOC;
    }

    ocnet_conn = ocnet_connection_new(httpd->evgrp);
    if (NULL == ocnet_conn) {
        goto L_ERROR_ONCCONN_NEW;
    }

    conncon->ocnet_conn = ocnet_conn;
    conncon->tcp_conn = tcp_conn;
    conncon->datalen = 0;
    INIT_LIST_HEAD(&conncon->link);
    ocnet_mutex_lock(httpd->conn_mutex);
    list_add_tail(&conncon->link, &httpd->conn_list);
    if (1 == httpd->internal_evgrp) {
        tcp_connection_event_enroll(tcp_conn, httpd->evgrp);
    }
    ocnet_mutex_unlock(httpd->conn_mutex);

    return conncon;

L_ERROR_ONCCONN_NEW:
    ocnet_free(conncon->swapbuf);
L_ERROR_SWAPBUF_ALLOC:
    ocnet_free(conncon->wbuf);
L_ERROR_WBUF_ALLOC:
    ocnet_free(conncon);
    return NULL;
}

static void *__acceptor(void *arg)
{
    ocnet_httpd_s_t *httpd = (ocnet_httpd_s_t *)arg;

    do {
        void *conn = tcp_server_accept(ONC_EVENT_TIMEOUT);
        if (NULL != conn) {
            __create_connection(httpd, conn);
        }
    } while (1 == httpd->running);

    return NULL;
}

int ocnet_httpd_init(int internal_evgrp, void *evgrp)
{
    if (tcp_server_init(1, NULL, 2) < 0) {
        return -1;
    }

    g_httpd.conn_mutex = ocnet_mutex_init();
    if (NULL == g_httpd.conn_mutex) {
        goto L_ERROR_CONNMUTEX_CREATE;
    }

    /* Create the msg buf used to communicate with core here */

    if (0 != internal_evgrp) {
        g_httpd.internal_evgrp = 1;
        g_httpd.evgrp = ocnet_evgrp_create(ONC_HTTPD_MAX_CONNS);
        if (NULL == g_httpd.evgrp) {
            goto L_ERROR_EVGRP_CREATE;
        }
    } else {
        if (NULL == evgrp) {
            goto L_ERROR_EVGRP_CREATE;
        }
        g_httpd.evgrp = evgrp;
    }

    INIT_LIST_HEAD(&g_httpd.listener_list);
    INIT_LIST_HEAD(&g_httpd.conn_list);

    return 0;

L_ERROR_EVGRP_CREATE:
    ocnet_mutex_destroy(g_httpd.conn_mutex);
L_ERROR_CONNMUTEX_CREATE:
    tcp_server_final();
    return -1;
}

int ocnet_httpd_listen(ocnet_ip_t ip, ocnet_port_t port)
{
    void *listener = NULL;
    ocnet_httpserver_s_t *server = NULL;

    listener = tcp_server_listen(ip, port, ONC_SERVER_MAX_CONNS);
    if (NULL == listener) {
        return -1;
    }

    server = ocnet_malloc(sizeof(ocnet_httpserver_s_t));
    if (NULL == server) {
        tcp_server_remove(listener);
        return -1;
    }

    server->listener = listener;
    INIT_LIST_HEAD(&server->link);

    list_add_tail(&server->link, &g_httpd.listener_list);

    return 0;
}

int ocnet_httpd_start(void)
{
    g_httpd.running = 1;
    g_httpd.acceptor = ocnet_thread_create(__acceptor, &g_httpd);
    if (NULL == g_httpd.acceptor) {
        return -1;
    }

    g_httpd.processor = ocnet_thread_create(__processor, &g_httpd);
    if (NULL == g_httpd.processor) {
        g_httpd.running = 0;
        ocnet_thread_join(g_httpd.acceptor);
        return -1;
    }

    return 0;
}

void ocnet_httpd_stop(void)
{
    g_httpd.running = 0;
    ocnet_thread_join(g_httpd.processor);
    ocnet_thread_join(g_httpd.acceptor);
}

void ocnet_httpd_final(void)
{
    ocnet_httpserver_s_t *server = NULL;
    ocnet_httpserver_s_t *n = NULL;
    ocnet_conncon_t *conn = NULL;
    ocnet_conncon_t *p = NULL;

    list_for_each_entry_safe(conn, p, &g_httpd.conn_list, link) {
        tcp_connection_del(conn->tcp_conn);
        list_del(&conn->link);
        ocnet_free(conn);
    }

    list_for_each_entry_safe(server, n, &g_httpd.listener_list, link) {
        tcp_server_remove(server->listener);
        list_del(&server->link);
        ocnet_free(server);
    }

    ocnet_evgrp_destroy(g_httpd.evgrp);
    ocnet_mutex_destroy(g_httpd.conn_mutex);
    tcp_server_final();
}
