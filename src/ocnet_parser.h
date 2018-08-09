#ifndef __ONC_PARSER____H__
#define __ONC_PARSER____H__

struct onc_parser_s;
typedef struct onc_parser_s     onc_parser_s_t;

typedef struct {
    int     fd;
} onc_parser_cb_s_t;

#ifdef __cplusplus
extern "C" {
#endif

onc_parser_s_t  *onc_parser_new(onc_parser_cb_s_t *callbacks);
int              onc_parser_parse(onc_parser_s_t *parser, char *buf, int len);
void             onc_parser_del(onc_parser_s_t *parser);

#ifdef __cplusplus
}
#endif

#endif
