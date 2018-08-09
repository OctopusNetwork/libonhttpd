#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "ocnet_httpd.h"

static int  g_running = 0;

static void __sigint_handler(int sig)
{
    g_running = 0;
}

int main(int argc, char *argv[])
{
    if (ocnet_httpd_init(1, NULL) < 0) {
        return -1;
    }

    if ((ocnet_httpd_listen(ocnet_iport_parse_ip("127.0.0.1"), 10688) < 0) ||
            (ocnet_httpd_listen(ocnet_iport_parse_ip("127.0.0.1"), 10689) < 0)) {
        ocnet_httpd_final();
        return -1;
    }

    if (ocnet_httpd_start() < 0) {
        ocnet_httpd_final();
        return -1;
    }

    signal(SIGINT, __sigint_handler);
    g_running = 1;

    do {
        sleep(5);
    } while (1 == g_running);

    ocnet_httpd_stop();
    ocnet_httpd_final();

    return 0;
}
