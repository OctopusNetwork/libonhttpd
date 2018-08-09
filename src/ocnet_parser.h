#ifndef __ONC_PARSER____H__
#define __ONC_PARSER____H__

struct ocnet_parser;
typedef struct ocnet_parser     ocnet_parser_t;

typedef struct {
    int     fd;
} ocnet_parser_cb_t;

#ifdef __cplusplus
extern "C" {
#endif

ocnet_parser_t  *ocnet_parser_new(ocnet_parser_cb_t *callbacks);
int              ocnet_parser_parse(ocnet_parser_t *parser, char *buf, int len);
void             ocnet_parser_del(ocnet_parser_t *parser);

#ifdef __cplusplus
}
#endif

#endif
