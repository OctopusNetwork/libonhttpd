#include <stdlib.h>
#include <stdio.h>

#include "http_parser.h"

#include "ocnet_malloc.h"

#include "ocnet_parser.h"

struct ocnet_parser {
    http_parser_settings    settings;
    http_parser             parser;

    ocnet_parser_cb_t       callbacks;
};

static int __on_message_begin(http_parser *parser)
{
    return 0;
}

static int __on_url(http_parser *parser, const char *buf, size_t size)
{
    return 0;
}

static int __on_status(http_parser *parser, const char *buf, size_t size)
{
    return 0;
}

static int __on_header_field(http_parser *parser, const char *buf, size_t size)
{
    return 0;
}

static int __on_header_value(http_parser *parser, const char *buf, size_t size)
{
    return 0;
}

static int __on_headers_complete(http_parser *parser)
{
    return 0;
}

static int __on_body(http_parser *parser, const char *buf, size_t size)
{
    return 0;
}

static int __on_message_complete(http_parser *parser)
{
    return 0;
}

static int __on_chunk_header(http_parser *parser)
{
    return 0;
}

static int __on_chunk_complete(http_parser *parser)
{
    return 0;
}

ocnet_parser_t *ocnet_parser_new(ocnet_parser_cb_t *callbacks)
{
    ocnet_parser_t *parser =
        ocnet_malloc(sizeof(ocnet_parser_t));

    if (NULL == parser) {
        return NULL;
    }

    http_parser_init(&parser->parser, HTTP_BOTH);

    parser->settings.on_message_begin = __on_message_begin;
    parser->settings.on_url = __on_url;
    parser->settings.on_status = __on_status;
    parser->settings.on_header_field = __on_header_field;
    parser->settings.on_header_value = __on_header_value;
    parser->settings.on_headers_complete = __on_headers_complete;
    parser->settings.on_body = __on_body;
    parser->settings.on_message_complete = __on_message_complete;
    parser->settings.on_chunk_header = __on_chunk_header;
    parser->settings.on_chunk_complete = __on_chunk_complete;

    ocnet_memcpy(&parser->callbacks, callbacks,
            sizeof(ocnet_parser_cb_t));

    return parser;
}

int ocnet_parser_parse(ocnet_parser_t *parser, char *buf, int len)
{
    int parsed_bytes = 0;

    parsed_bytes = http_parser_execute(&parser->parser,
            &parser->settings, buf, len);
    if (0 == parser->parser.http_errno) {
        return parsed_bytes;
    }

    printf("Http parser error---%d\n", parser->parser.http_errno);
    return -1;
}

void ocnet_parser_del(ocnet_parser_t *parser)
{
    free(parser);
}
