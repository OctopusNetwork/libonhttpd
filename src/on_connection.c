#include <stdint.h>

#include "on_malloc.h"

#include "onlfds.h"
#include "onevent.h"
#include "onevgrp.h"

#include "http_request.h"
#include "on_connection.h"

typedef enum {
    N_CONN_IDLE,
    N_CONN_REQUEST_START,
    N_CONN_READ,
    N_CONN_REQUEST_END,
    N_CONN_READ_POST,
    N_CONN_HANDLE_REQUEST,
    N_CONN_RESPONSE_START,
    N_CONN_WRITE,
    N_CONN_RESPONSE_END,
    N_CONN_ERROR,
    N_CONN_CLOSE
} onc_connstat_e_t;

#define ONC_MAX_RECVBUF_LEN     (1024 * 1024)

static uint32_t     g_conn_id = 0;

typedef struct onc_connection_s {
    uint32_t            conn_id;
    onc_connstat_e_t    state;
    onc_httpreq_s_t    *request;
    char                recvbuf[ONC_MAX_RECVBUF_LEN];
    uint32_t            recvlen;
    uint64_t            sendlen;

    /* This event should listen at producer's waiter */
    void               *data_event;
    unsigned char       data_exhausted:     1;

    void               *evgrp;
} onc_connection_s_t;

onc_connection_s_t *onc_connection_new(void *evgrp)
{
    onc_connection_s_t *onc_conn =
        onc_malloc(sizeof(onc_connection_s_t));

    if (NULL == onc_conn) {
        return NULL;
    }

    onc_conn->request = http_request_new();
    if (NULL == onc_conn->request) {
        goto L_ERROR_HTTPREQUEST_NEW;
    }

    onc_conn->data_event = onc_event_create(1,
            ONC_EVENT_READ | ONC_EVENT_ERROR, 1, 0, 0);
    if (NULL == onc_conn->data_event) {
        goto L_ERROR_DATAEVENT_CREATE;
    }

    onc_evgrp_event_add(evgrp, onc_conn->data_event);

    onc_conn->state = N_CONN_REQUEST_START;
    onc_conn->recvlen = 0;
    onc_memset(onc_conn->recvbuf, 0x0, ONC_MAX_RECVBUF_LEN);
    onc_conn->conn_id = g_conn_id++;
    onc_conn->sendlen = 0;
    onc_conn->data_exhausted = 1;
    onc_conn->evgrp = evgrp;

    return onc_conn;

L_ERROR_DATAEVENT_CREATE:
    http_request_del(onc_conn->request);
L_ERROR_HTTPREQUEST_NEW:
    onc_free(onc_conn);
    return NULL;
}

static void __set_state(onc_connection_s_t *onc_conn, onc_connstat_e_t state)
{
    onc_conn->state = state;
}

int onc_connection_feed(onc_connection_s_t *onc_conn, char *buf, int len)
{
    int rc = 0;

    switch (onc_conn->state) {
    case N_CONN_REQUEST_START:
        __set_state(onc_conn, N_CONN_READ);
        break;
    default:
        break;
    }

    /* How to decide the end of request string ? */
    switch (onc_conn->state) {
    case N_CONN_READ:
        onc_memcpy(onc_conn->recvbuf + onc_conn->recvlen, buf, len);
        onc_conn->recvlen += len;
        __set_state(onc_conn, N_CONN_REQUEST_END);
        break;
    default:
        break;
    }

    switch (onc_conn->state) {
    case N_CONN_REQUEST_END:
        rc = http_request_parse(onc_conn->request, buf, len);
        if (rc < 0) {
            __set_state(onc_conn, N_CONN_READ);
        }
        /* If it's post method, read post body */
        /* Parse OK, let router handler process the request */
        /**
         * The connection's conn_id will be used as key
         * to let data producer to generate data to right
         * place
         */
        break;
    default:
        break;
    }

    return 0;
}

int onc_connection_grab(onc_connection_s_t *onc_conn, char *buf, int len)
{
    /* Grab data from data producer according to conn_id */
    /**
     * Check if data is produced, if consumer cannot consum data
     * one time, it should read it again
     */

    onc_memcpy(buf, "Request OK", 12);

    return 12;
}

int onc_connection_eof(onc_connection_s_t *onc_conn)
{
    return 0;
}

int onc_connection_data_available(onc_connection_s_t *onc_conn, void *lfds)
{
    return onc_event_happen(onc_conn->data_event, lfds, ONC_EVENT_READ);
}

void onc_connection_del(onc_connection_s_t *onc_conn)
{
    onc_evgrp_event_del(onc_conn->evgrp, onc_conn->data_event);
    onc_event_destroy(onc_conn->data_event);
    http_request_del(onc_conn->request);
    onc_free(onc_conn);
}
