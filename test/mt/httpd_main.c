#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "onhttpd.h"

static int  g_running = 0;

static void __sigint_handler(int sig)
{
    g_running = 0;
}

int main(int argc, char *argv[])
{
    if (onc_httpd_init(1, NULL) < 0) {
        return -1;
    }

    if ((onc_httpd_listen(onc_iport_parse_ip("127.0.0.1"), 10688) < 0) ||
            (onc_httpd_listen(onc_iport_parse_ip("127.0.0.1"), 10689) < 0)) {
        onc_httpd_final();
        return -1;
    }

    if (onc_httpd_start() < 0) {
        onc_httpd_final();
        return -1;
    }

    signal(SIGINT, __sigint_handler);
    g_running = 1;

    do {
        sleep(5);
    } while (1 == g_running);

    onc_httpd_stop();
    onc_httpd_final();

    return 0;
}
