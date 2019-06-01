#include "vpn-ws.h"

#include <netdb.h>
#include <regex.h>



int vpn_ws_full_write(int fd, uint8_t *buf, size_t len) {
    size_t remains = len;
    uint8_t *ptr = buf;
    while(remains > 0) {
        ssize_t wlen = write(fd, ptr, remains);
        if (wlen <= 0) {
            if (wlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) {
                fd_set wset;
                FD_ZERO(&wset);
                FD_SET(fd, &wset);
                if (select(fd+1, NULL, &wset, NULL, NULL) < 0) { vpn_ws_error("vpn_ws_full_write()/select()"); return -1; }
                continue;
            }
            vpn_ws_error("vpn_ws_full_write()/write()");
            return -1;
        }
        ptr += wlen;
        remains -= wlen;
    }
    return 0;
}

void vpn_ws_client_destroy(vpn_ws_peer *peer) {
    if (vpn_ws_conf.ssl_ctx) { vpn_ws_ssl_close(vpn_ws_conf.ssl_ctx, peer->fd); }
    vpn_ws_peer_destroy(peer);
}

int vpn_ws_client_read(vpn_ws_peer *peer, uint64_t amount) {
    uint64_t available = peer->len - peer->pos;
    if (available < amount) {
        peer->len += amount;
        void *tmp = realloc(peer->buf, peer->len);
        if (!tmp) { vpn_ws_error("vpn_ws_client_read()/realloc()"); return -1; }
        peer->buf = tmp;
    }
    ssize_t rlen;
    if (vpn_ws_conf.ssl_ctx) {
        rlen = vpn_ws_ssl_read(vpn_ws_conf.ssl_ctx, peer->buf + peer->pos, amount);
        if (rlen == 0) { return -1; }
        if (rlen > 0) { peer->pos += rlen; return 0; }
        return rlen;
    } else rlen = read(peer->fd, peer->buf + peer->pos, amount);
    if (rlen < 0) {
        if (rlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) return 0;
        vpn_ws_error("vpn_ws_client_read()/read()"); return -1;
    } else if (rlen == 0) { return -1; }
    peer->pos += rlen;
    return 0;
}

int vpn_ws_client_write(vpn_ws_peer *peer, uint8_t *buf, size_t len) {
    if (vpn_ws_conf.ssl_ctx) { return vpn_ws_ssl_write(vpn_ws_conf.ssl_ctx, buf, len); }
    return vpn_ws_full_write(peer->fd, buf, len);
}






int vpn_ws_connect(vpn_ws_peer *peer, char *name) {
    char *cpy = NULL;
    cpy = strdup(name);

    int ssl = 0;
    uint16_t port = 80;
    if (strlen(cpy) < 6) {
        vpn_ws_log("invalid websocket url: %s\n", cpy);
        vpn_ws_exit(EXIT_FAILURE);
    }

    if      (!strncmp(cpy, "wss://", 6)) { ssl = 1; port = 443; }
    else if (!strncmp(cpy, "ws://",  5)) { ssl = 0; port = 80;  }
    else {
        vpn_ws_log("invalid websocket url: %s (requires ws:// or wss://)\n", cpy);
        vpn_ws_exit(EXIT_FAILURE);
    }

    char *path = NULL;

    // now get the domain part
    char *domain = cpy + 5 + ssl;
    size_t domain_len = strlen(domain);
    char *slash = strchr(domain, '/');
    if (slash) { domain_len = slash - domain;  domain[domain_len] = 0; path = slash + 1; }

    // check for basic auth
    char *at = strchr(domain, '@');
    if (at) { *at = 0; domain = at+1; domain_len = strlen(domain); }

    // check for port
    char *port_str = strchr(domain, ':');
    if (port_str) { *port_str = 0; domain_len = strlen(domain); port = atoi(port_str+1); }

    vpn_ws_log(" + connecting to %s port %u (transport: %s)\n", domain, port, ssl ? "wss": "ws");

    // resolve the domain
    struct hostent *he = gethostbyname(domain);
    if (!he) {
        vpn_ws_log(" - connect: unable to resolve name %s\n", domain);
        return -1;
    }

    peer->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer->fd < 0) {
        vpn_ws_log(" - connect: unable to open socket\n");
        return -1;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr = *((struct in_addr *) he->h_addr);

    if (connect(peer->fd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in))) {
        vpn_ws_log(" - connect: unable to connect\n");
        return -1;
    }

    char *auth = NULL;

    if (at) {
        char *crd = cpy + 5 + ssl;
        auth = vpn_ws_calloc(23 + (strlen(crd) * 2));
        if (!auth) {
            vpn_ws_log(" - connect: unable to make auth string\n");
            return -1;
        }
        memcpy(auth, "Authorization: Basic ", 21);
        uint16_t auth_len = vpn_ws_base64_encode((uint8_t *)crd, strlen(crd), (uint8_t *)auth + 21);
        memcpy(auth + 21 + auth_len, "\r\n", 2);
    }

    uint8_t *mac = vpn_ws_conf.tuntap_mac;
    // now build and send the request
    uint8_t key[32];
    uint8_t secret[10];

    for(int i=0; i<10; i++) secret[i] = rand();

    char buf[8192];
    memset(buf, 0, 8192);
    int ret = snprintf(buf, 8192, "GET /%s HTTP/1.1\r\nHost: %s%s%s\r\n%sUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %.*s\r\nX-vpn-ws-MAC: %02x:%02x:%02x:%02x:%02x:%02x%s\r\n\r\n",
        path ? path : "",
        domain,
        port_str ? ":" : "",
        port_str ? port_str+1 : "",
        auth ? auth : "",
        vpn_ws_base64_encode(secret, 10, key),
        key,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        vpn_ws_conf.bridge ? "\r\nX-vpn-ws-bridge: on" : ""
    );

    if (auth) free(auth);
    if (ret == 0 || ret > 8192) { vpn_ws_log(" - connect: unable to copy buf. Mem?\n"); return -1; }

    if (ssl) {
        vpn_ws_conf.ssl_ctx = vpn_ws_ssl_handshake(peer, domain, vpn_ws_conf.ssl_key, vpn_ws_conf.ssl_crt);
        if (vpn_ws_conf.ssl_ctx) {
            if (vpn_ws_ssl_write(vpn_ws_conf.ssl_ctx, (uint8_t*)buf, ret) != ret) {
                vpn_ws_log(" - connect: first TLS request not normal\n");
                return -1;
            }
        } else {
            vpn_ws_log(" - connect: need TLS session\n");
            return -1;
        }

    } else { // plain mode
        if (vpn_ws_full_write(peer->fd, (uint8_t*)buf, ret) != ret) {
            vpn_ws_log(" - connect: first request not normal\n");
            return -1;
        }
    }

    memset(buf, 0, 8192);
    if (ssl) vpn_ws_ssl_read(vpn_ws_conf.ssl_ctx, (uint8_t*)buf, 8192); else read(peer->fd, buf, 8192);
    if (strlen(buf) > 20) {
        regex_t regex;
        regcomp(&regex, "http.* 101 .*upgrade", REG_ICASE);
        if (regexec(&regex, buf, 0, NULL, 0) == REG_NOERROR) {
            regfree(&regex);
            vpn_ws_log(" + connected to %s port %u (transport: %s)\n", domain, port, ssl ? "wss": "ws");
            return 0;
        }
        regfree(&regex);
        vpn_ws_log(" - connect: server disagree UPGRADE\n");
    } else vpn_ws_log(" - connect: server responded shortly: %s\n", buf);

    return -1;
}




static struct option vpn_ws_options[] = {
    {"exec",      required_argument, NULL, 1 },
    {"key",       required_argument, NULL, 2 },
    {"crt",       required_argument, NULL, 3 },
    {"mtu",       required_argument, NULL, 4 },
    {"timeout",   required_argument, NULL, 5 },
    {"ping",      required_argument, NULL, 6 },
    {"no-verify", no_argument,       NULL, 7 },
    {"bridge",    no_argument,       NULL, 8 },
    {NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
    sigset_t sset;
    sigemptyset(&sset);
    sigaddset(&sset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sset, NULL);

    vpn_ws_conf.exec    = NULL;
    vpn_ws_conf.ssl_key = NULL;
    vpn_ws_conf.ssl_crt = NULL;
    vpn_ws_conf.mtu           = 1484;
    vpn_ws_conf.timeout       = 30;
    vpn_ws_conf.ping          = 15;
    vpn_ws_conf.ssl_no_verify = 0;
    vpn_ws_conf.bridge        = 0;


    int ii, option_index = 0;
    for(;;) {
        int c = getopt_long(argc, argv, "", vpn_ws_options, &option_index);
        if (c < 0) break;
        switch(c) {
            case 0: break;
            case 1: vpn_ws_conf.exec = optarg; break;
            case 2: vpn_ws_conf.ssl_key = optarg; break;
            case 3: vpn_ws_conf.ssl_crt = optarg; break;
            case 4:
                ii = atoi(optarg);
                if (ii < 64 || ii > 1518) {printf("Incorrect MTU! [64-1518]\n"); vpn_ws_exit(EXIT_FAILURE);}
                vpn_ws_conf.mtu = ii;
                break;
            case 5:
                ii = atoi(optarg);
                if (ii < 1 || ii > __INT_MAX__) {printf("Incorrect timeout! [1-%d]\n",__INT_MAX__); vpn_ws_exit(EXIT_FAILURE);}
                vpn_ws_conf.timeout = ii;
                break;
            case 6:
                ii = atoi(optarg);
                if (ii < 1 || ii > 4096) {printf("Incorrect ping! [1-4096]\n"); vpn_ws_exit(EXIT_FAILURE);}
                vpn_ws_conf.ping = ii;
                break;
            case 7: vpn_ws_conf.ssl_no_verify = 1; break;
            case 8: vpn_ws_conf.bridge        = 1; break;
            case '?':break;
            default:
                printf("error parsing arguments!\n");
        }
    }

    if (optind + 1 >= argc) {
        printf("syntax: %s <tap> <ws> arguments...\n\n", argv[0]);
        printf("Optional arguments:\n");
        printf("  --exec \"<command>\"\t\tcommand to configure TAP device\n");
        printf("  --key \"<file>\"\t\tclient secret key\n");
        printf("  --crt \"<file>\"\t\tclient certificate\n");
        printf("  --mtu 1500\t\t\tCustomize for better packet transfer\n");
        printf("  --timeout <sec>\t\tTime to reconnect\n");
        printf("  --ping <sec>\t\t\tExchange short packets\n");
        printf("  --no-verify <1|0>\t\tSkip check server certificate\n");
        printf("  --bridge <1|0>\t\tBridge mode\n");
        vpn_ws_exit(EXIT_FAILURE);
    }

    vpn_ws_conf.tuntap_name = argv[optind];
    vpn_ws_conf.server_addr = argv[optind+1];

    vpn_ws_log("current options:\n");
    vpn_ws_log("    tuntap %s\n", vpn_ws_conf.tuntap_name);
    vpn_ws_log("    server %s\n", vpn_ws_conf.server_addr);
    if (vpn_ws_conf.exec)    vpn_ws_log("      exec %s\n", vpn_ws_conf.exec);
    if (vpn_ws_conf.ssl_key) vpn_ws_log("       key %s\n", vpn_ws_conf.ssl_key);
    if (vpn_ws_conf.ssl_crt) vpn_ws_log("       crt %s\n", vpn_ws_conf.ssl_crt);
    vpn_ws_log("       mtu %d\n", vpn_ws_conf.mtu);
    vpn_ws_log("   timeout %d\n", vpn_ws_conf.timeout);
    vpn_ws_log("      ping %d\n", vpn_ws_conf.ping);
    vpn_ws_log(" no-verify %d\n", vpn_ws_conf.ssl_no_verify);
    vpn_ws_log("    bridge %d\n", vpn_ws_conf.bridge);

    // initialize rnd engine
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand((unsigned int) (tv.tv_usec * tv.tv_sec));

    int tuntap_fd = vpn_ws_tuntap(vpn_ws_conf.tuntap_name);
    if (tuntap_fd < 0) {
        vpn_ws_log("FATAL on start: TUNTAP %s not open in mode O_RDWR", vpn_ws_conf.tuntap_name);
        vpn_ws_exit(EXIT_FAILURE);
    }

    if (vpn_ws_nb(tuntap_fd)) {
        vpn_ws_log("FATAL on start: TUNTAP %s !O_NONBLOCK", vpn_ws_conf.tuntap_name);
        vpn_ws_exit(EXIT_FAILURE);
    }

    if (vpn_ws_conf.exec) {
        if (vpn_ws_exec(vpn_ws_conf.exec)) {
            vpn_ws_log("FATAL on \"%s\" after open TUNTAP %s", vpn_ws_conf.exec, vpn_ws_conf.tuntap_name);
            vpn_ws_exit(EXIT_FAILURE);
        }
    }

    int throttle = -1;

reconnect: // back here whenever the server disconnect

    if (throttle > -1) vpn_ws_log(" - disconnected\n");
    if (throttle >= 20) throttle = 0;
    throttle = throttle + 2;
    if (throttle) sleep(throttle);

    vpn_ws_peer *peer = vpn_ws_calloc(sizeof(vpn_ws_peer));
    if (!peer) { vpn_ws_log(" - !calloc peer struct. Mem?\n"); goto reconnect; } // MEM PROBLEM?

    memcpy(peer->mac, vpn_ws_conf.tuntap_mac, 6);
    peer->timeout = 1000 * vpn_ws_conf.timeout;
    peer->ping = vpn_ws_conf.ping;

    if (vpn_ws_connect(peer, vpn_ws_conf.server_addr)) { vpn_ws_log(" - !connect peer to server\n"); goto reconnect; }

    // we set the socket in non blocking mode, albeit the code paths are all blocking
    // it is only a secuity measure to avoid dead-blocking the process (as an example select() on Linux is a bit flacky)
    if (vpn_ws_nb(peer->fd)) { vpn_ws_log(" - !O_NONBLOCK for my peer\n"); vpn_ws_client_destroy(peer); goto reconnect; }

    uint8_t mask[4]; mask[0] = rand(); mask[1] = rand(); mask[2] = rand(); mask[3] = rand();

    // find the highest fd
    int max_fd = peer->fd;
    if (tuntap_fd > max_fd) max_fd = tuntap_fd;
    max_fd++;

    fd_set rset;
    for(;;) {
        FD_ZERO(&rset);
        FD_SET(peer->fd, &rset);
        FD_SET(tuntap_fd, &rset);
        tv.tv_sec = peer->ping;
        tv.tv_usec = 0;
        int ret = select(max_fd, &rset, NULL, NULL, &tv);
        if (ret < 0) { // the process manager will save us here
            vpn_ws_error("FATAL on loop: select < 0");
            vpn_ws_exit(EXIT_FAILURE);
        }
        if (ret == 0) { // too much inactivity, send a ping
            if (vpn_ws_client_write(peer, (uint8_t*)"\x89\x00", 2) != 2) {
                vpn_ws_client_destroy(peer);
                vpn_ws_log(" - ERR on inactivity ping\n");
                goto reconnect;
            }
            continue;
        }

        if (FD_ISSET(peer->fd, &rset)) {
            if (vpn_ws_client_read(peer, 8192) < 0) {
                vpn_ws_client_destroy(peer);
                vpn_ws_log(" - ERR on loop: client_read<0\n");
                goto reconnect;
            }
            // start getting websocket packets
            for(;;) {
                uint16_t ws_header = 0;
                int64_t rlen = vpn_ws_websocket_parse(peer, &ws_header);
                if (rlen < 0) {
                    vpn_ws_client_destroy(peer);
                    vpn_ws_log(" - ERR on loop: websocket_parse<0\n");
                    goto reconnect;
                } else if (rlen == 0) break;

                // ignore packet ?
                if (ws_header != 0) { //  goto decapitate;
                    // is it a masked packet ?
                    uint8_t *ws = peer->buf + ws_header;
                    uint64_t ws_len = rlen - ws_header;
                    if (peer->has_mask) { for (uint16_t i=0; i<ws_len; i++) { ws[i] = ws[i] ^ peer->mask[i % 4]; } }
                    if (vpn_ws_full_write(tuntap_fd, ws, ws_len)) {
                        vpn_ws_error("FATAL on loop: full_write to TUN/TAP device");
                        // being not able to write on tuntap is really bad...
                        vpn_ws_exit(EXIT_FAILURE);
                    }
                }
//                 decapitate:
                memmove(peer->buf, peer->buf + rlen, peer->pos - rlen);
                peer->pos -= rlen;
            }
        }

        if (FD_ISSET(tuntap_fd, &rset)) {
            // we use this buffer for the websocket packet too 2 byte header + 2 byte size + 4 bytes masking + mtu
            uint8_t mtu[8+vpn_ws_conf.mtu];
            ssize_t rlen = read(tuntap_fd, mtu+8, vpn_ws_conf.mtu);
            if (rlen <= 0) {
                if (rlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) continue;
                vpn_ws_error("FATAL on loop: read from TUN/TAP device");
                vpn_ws_exit(EXIT_FAILURE);
            }

            for (ssize_t i=0; i<rlen; i++) { mtu[8+i] = mtu[8+i] ^ mask[i % 4]; } // mask packet
            mtu[4] = mask[0]; mtu[5] = mask[1]; mtu[6] = mask[2]; mtu[7] = mask[3];

            if (rlen < 126) {
                mtu[2] = 0x82;
                mtu[3] = rlen | 0x80;
                if (vpn_ws_client_write(peer, mtu + 2, rlen + 6) != rlen + 6) {
                    vpn_ws_client_destroy(peer);
                    vpn_ws_log(" - ERR on loop: small client_write size not match\n");
                    goto reconnect;
                }
            } else {
                mtu[0] = 0x82;
                mtu[1] = 126 | 0x80;
                mtu[2] = (uint8_t) ((rlen >> 8) & 0xff);
                mtu[3] = (uint8_t) (rlen & 0xff);
                if (vpn_ws_client_write(peer, mtu, rlen + 8) != rlen + 8) {
                    vpn_ws_client_destroy(peer);
                    vpn_ws_log(" - ERR on loop: large client_write size not match\n");
                    goto reconnect;
                }
            }
        } // FD_ISSET tuntap_fd

    }
    return (EXIT_FAILURE);
}
