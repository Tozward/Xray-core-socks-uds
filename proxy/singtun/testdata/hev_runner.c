#include <signal.h>
#include <unistd.h>
#include <hev-socks5-tunnel.h>

static void stop_tunnel(int signal_number)
{
    (void)signal_number;
    hev_socks5_tunnel_quit();
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    signal(SIGINT, stop_tunnel);
    signal(SIGTERM, stop_tunnel);
    int result = hev_socks5_tunnel_main_from_file(argv[1], 3);
    close(3);
    return result < 0 ? 1 : 0;
}
