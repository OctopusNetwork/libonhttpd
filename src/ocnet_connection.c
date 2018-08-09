#include <stdint.h>

#include "ocnet_malloc.h"

#include "onlfds.h"
#include "onevent.h"
#include "onevgrp.h"

#include "http_request.h"
#include "ocnet_connection.h"

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
} ocnet_connstat_t;

#define OCNET_MAX_RECVBUF_LEN     (1024 * 1024)

static uint32_t     g_conn_id = 0;

typedef struct ocnet_connection {
    uint32_t            conn_id;
    ocnet_connstat_t    state;
    ocnet_httpreq_t    *request;
    char                recvbuf[OCNET_MAX_RECVBUF_LEN];
    uint32_t            recvlen;
    uint64_t            sendlen;

    /* This event should listen at producer's waiter */
    void               *data_event;
    unsigned char       data_exhausted:     1;

    void               *evgrp;
} ocnet_connection_t;

ocnet_connection_t *ocnet_connection_new(void *evgrp)
{
    ocnet_connection_t *ocnet_conn =
        ocnet_malloc(sizeof(ocnet_connection_t));

    if (NULL == ocnet_conn) {
        return NULL;
    }

    ocnet_conn->request = http_request_new();
    if (NULL == ocnet_conn->request) {
        goto L_ERROR_HTTPREQUEST_NEW;
    }

    ocnet_conn->data_event = ocnet_event_create(1,
            OCNET_EVENT_READ | OCNET_EVENT_ERROR, 1, 0, 0);
    if (NULL == ocnet_conn->data_event) {
        goto L_ERROR_DATAEVENT_CREATE;
    }

    ocnet_evgrp_event_add(evgrp, ocnet_conn->data_event);

    ocnet_conn->state = N_CONN_REQUEST_START;
    ocnet_conn->recvlen = 0;
    ocnet_memset(ocnet_conn->recvbuf, 0x0, OCNET_MAX_RECVBUF_LEN);
    ocnet_conn->conn_id = g_conn_id++;
    ocnet_conn->sendlen = 0;
    ocnet_conn->data_exhausted = 1;
    ocnet_conn->evgrp = evgrp;

    return ocnet_conn;

L_ERROR_DATAEVENT_CREATE:
    http_request_del(ocnet_conn->request);
L_ERROR_HTTPREQUEST_NEW:
    ocnet_free(ocnet_conn);
    return NULL;
}

static void __set_state(ocnet_connection_t *ocnet_conn, ocnet_connstat_t state)
{
    ocnet_conn->state = state;
}

int ocnet_connection_feed(ocnet_connection_t *ocnet_conn, char *buf, int len)
{
    int rc = 0;

    switch (ocnet_conn->state) {
    case N_CONN_REQUEST_START:
        __set_state(ocnet_conn, N_CONN_READ);
        break;
    default:
        break;
    }

    /* How to decide the end of request string ? */
    switch (ocnet_conn->state) {
    case N_CONN_READ:
        ocnet_memcpy(ocnet_conn->recvbuf + ocnet_conn->recvlen, buf, len);
        ocnet_conn->recvlen += len;
        __set_state(ocnet_conn, N_CONN_REQUEST_END);
        break;
    default:
        break;
    }

    switch (ocnet_conn->state) {
    case N_CONN_REQUEST_END:
        rc = http_request_parse(ocnet_conn->request, buf, len);
        if (rc < 0) {
            __set_state(ocnet_conn, N_CONN_READ);
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

int ocnet_connection_grab(ocnet_connection_t *ocnet_conn, char *buf, int len)
{
    /* Grab data from data producer according to conn_id */
    /**
     * Check if data is produced, if consumer cannot consum data
     * one time, it should read it again
     */

    ocnet_memcpy(buf, "Request OK", 12);

    return 12;
}

int ocnet_connection_eof(ocnet_connection_t *ocnet_conn)
{
    return 0;
}

int ocnet_connection_data_available(ocnet_connection_t *ocnet_conn, void *lfds)
{
    return ocnet_event_happen(ocnet_conn->data_event, lfds, OCNET_EVENT_READ);
}

void ocnet_connection_del(ocnet_connection_t *ocnet_conn)
{
    ocnet_evgrp_event_del(ocnet_conn->evgrp, ocnet_conn->data_event);
    ocnet_event_destroy(ocnet_conn->data_event);
    http_request_del(ocnet_conn->request);
    ocnet_free(ocnet_conn);
}
