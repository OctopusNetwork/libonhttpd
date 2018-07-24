#include "on_malloc.h"
#include "on_thread.h"

#include "on_log.h"

#include "list.h"

#include "onlfds.h"
#include "onevgrp.h"

#include "tcp_connection.h"
#include "tcp_server.h"

#include "onhttpd.h"

#include "on_connection.h"

#define ONC_HTTPD_MAX_CONNS     128
#define ONC_SERVER_MAX_CONNS    32
#define ONC_EVENT_TIMEOUT       500
#define ONC_WRITE_BUFLEN        (1024 * 1024)

#define TAG     "httpd"

typedef struct {
    void               *tcp_conn;
    void               *http_request;
    onc_connection_s_t *onc_conn;
    char               *wbuf;
    char               *swapbuf;
    char                datalen;
    struct list_head    link;
} onc_conncon_s_t;

typedef struct {
    void               *listener;
    struct list_head    link;
} onc_httpserver_s_t;

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
} onc_httpd_s_t;

static onc_httpd_s_t    g_httpd;

static int __on_read(onc_conncon_s_t *conn, void *lfds)
{
    void *tcp_conn = conn->tcp_conn;
    if (0 != tcp_connection_readable(tcp_conn, lfds)) {
        char buf[1024] = {0};
        int readlen = tcp_connection_read(tcp_conn, buf, sizeof(buf));
        if (0 < readlen) {
            onc_connection_feed(conn->onc_conn, buf, readlen);
        } else if (readlen < 0) {
            return -1;
        }
    }
    return 0;
}

static int __on_error(onc_conncon_s_t *conn, void *lfds)
{
    void *tcp_conn = conn->tcp_conn;
    return tcp_connection_error(tcp_conn, lfds);
}

static int __on_write(onc_conncon_s_t *conn, void *lfds)
{
    void *tcp_conn = conn->tcp_conn;
    onc_connection_s_t *onc_conn = conn->onc_conn;

    if (0 == onc_connection_eof(onc_conn)) {
        if (0 != tcp_connection_writable(tcp_conn, lfds) ||
                0 != onc_connection_data_available(onc_conn, lfds)) {
            int writelen = 0;
            int buflen = sizeof(conn->wbuf) - conn->datalen;
            int grablen = onc_connection_grab(
                    onc_conn, conn->wbuf + conn->datalen, buflen);

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
                        onc_memcpy(conn->swapbuf, conn->wbuf + writelen,
                                conn->datalen);
                        onc_memcpy(conn->wbuf, conn->swapbuf, conn->datalen);
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
        onc_httpd_s_t *httpd, onc_conncon_s_t *conn)
{
    onc_free(conn->swapbuf);
    onc_free(conn->wbuf);
    onc_connection_del(conn->onc_conn);
    onc_mutex_lock(httpd->conn_mutex);
    list_del(&conn->link);
    if (1 == httpd->internal_evgrp) {
        tcp_connection_event_del(conn->tcp_conn, httpd->evgrp);
    }
    onc_mutex_unlock(httpd->conn_mutex);
    tcp_connection_del(conn->tcp_conn);
    onc_free(conn);
}

static int __on_event(onc_httpd_s_t *httpd, void *lfds)
{
    onc_conncon_s_t *conn = NULL;
    onc_conncon_s_t *p = NULL;

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
    onc_httpd_s_t *httpd = (onc_httpd_s_t *)arg;
    void *lfds = onc_lfds_new();

    if (NULL == lfds) {
        return NULL;
    }

    do {
        int rc = 0;
        rc = onc_evgrp_wait(httpd->evgrp, ONC_EVENT_TIMEOUT, lfds);
        if (rc < 0) {
            LOGI(TAG, "event wait error");
        } else if (0 < rc) {
            __on_event(httpd, lfds);
        } else {
            LOGI(TAG, "event wait timeout");
        }
    } while (1 == httpd->running);

    onc_lfds_del(lfds);

    return NULL;
}

static onc_conncon_s_t *__create_connection(
        onc_httpd_s_t *httpd, void *tcp_conn)
{
    onc_connection_s_t *onc_conn = NULL;
    onc_conncon_s_t *conncon = NULL;

    conncon = onc_malloc(sizeof(onc_conncon_s_t));
    if (NULL == conncon) {
        return NULL;
    }

    conncon->wbuf = onc_malloc(ONC_WRITE_BUFLEN);
    if (NULL == conncon->wbuf) {
        goto L_ERROR_WBUF_ALLOC;
    }

    conncon->swapbuf = onc_malloc(ONC_WRITE_BUFLEN);
    if (NULL == conncon->swapbuf) {
        goto L_ERROR_SWAPBUF_ALLOC;
    }

    onc_conn = onc_connection_new(httpd->evgrp);
    if (NULL == onc_conn) {
        goto L_ERROR_ONCCONN_NEW;
    }

    conncon->onc_conn = onc_conn;
    conncon->tcp_conn = tcp_conn;
    conncon->datalen = 0;
    INIT_LIST_HEAD(&conncon->link);
    onc_mutex_lock(httpd->conn_mutex);
    list_add_tail(&conncon->link, &httpd->conn_list);
    if (1 == httpd->internal_evgrp) {
        tcp_connection_event_enroll(tcp_conn, httpd->evgrp);
    }
    onc_mutex_unlock(httpd->conn_mutex);

    return conncon;

L_ERROR_ONCCONN_NEW:
    onc_free(conncon->swapbuf);
L_ERROR_SWAPBUF_ALLOC:
    onc_free(conncon->wbuf);
L_ERROR_WBUF_ALLOC:
    onc_free(conncon);
    return NULL;
}

static void *__acceptor(void *arg)
{
    onc_httpd_s_t *httpd = (onc_httpd_s_t *)arg;

    do {
        void *conn = tcp_server_accept(ONC_EVENT_TIMEOUT);
        if (NULL != conn) {
            __create_connection(httpd, conn);
        }
    } while (1 == httpd->running);

    return NULL;
}

int onc_httpd_init(int internal_evgrp, void *evgrp)
{
    if (tcp_server_init(1, NULL, 2) < 0) {
        return -1;
    }

    g_httpd.conn_mutex = onc_mutex_init();
    if (NULL == g_httpd.conn_mutex) {
        goto L_ERROR_CONNMUTEX_CREATE;
    }

    /* Create the msg buf used to communicate with core here */

    if (0 != internal_evgrp) {
        g_httpd.internal_evgrp = 1;
        g_httpd.evgrp = onc_evgrp_create(ONC_HTTPD_MAX_CONNS);
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
    onc_mutex_destroy(g_httpd.conn_mutex);
L_ERROR_CONNMUTEX_CREATE:
    tcp_server_final();
    return -1;
}

int onc_httpd_listen(onc_ip_t ip, onc_port_t port)
{
    void *listener = NULL;
    onc_httpserver_s_t *server = NULL;

    listener = tcp_server_listen(ip, port, ONC_SERVER_MAX_CONNS);
    if (NULL == listener) {
        return -1;
    }

    server = onc_malloc(sizeof(onc_httpserver_s_t));
    if (NULL == server) {
        tcp_server_remove(listener);
        return -1;
    }

    server->listener = listener;
    INIT_LIST_HEAD(&server->link);

    list_add_tail(&server->link, &g_httpd.listener_list);

    return 0;
}

int onc_httpd_start(void)
{
    g_httpd.running = 1;
    g_httpd.acceptor = onc_thread_create(__acceptor, &g_httpd);
    if (NULL == g_httpd.acceptor) {
        return -1;
    }

    g_httpd.processor = onc_thread_create(__processor, &g_httpd);
    if (NULL == g_httpd.processor) {
        g_httpd.running = 0;
        onc_thread_join(g_httpd.acceptor);
        return -1;
    }

    return 0;
}

void onc_httpd_stop(void)
{
    g_httpd.running = 0;
    onc_thread_join(g_httpd.processor);
    onc_thread_join(g_httpd.acceptor);
}

void onc_httpd_final(void)
{
    onc_httpserver_s_t *server = NULL;
    onc_httpserver_s_t *n = NULL;
    onc_conncon_s_t *conn = NULL;
    onc_conncon_s_t *p = NULL;

    list_for_each_entry_safe(conn, p, &g_httpd.conn_list, link) {
        tcp_connection_del(conn->tcp_conn);
        list_del(&conn->link);
        onc_free(conn);
    }

    list_for_each_entry_safe(server, n, &g_httpd.listener_list, link) {
        tcp_server_remove(server->listener);
        list_del(&server->link);
        onc_free(server);
    }

    onc_evgrp_destroy(g_httpd.evgrp);
    onc_mutex_destroy(g_httpd.conn_mutex);
    tcp_server_final();
}
