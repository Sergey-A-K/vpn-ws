#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>

#include "sha1.h"

#include <grp.h>
#include <pwd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/ocsp.h>

#define GNUTLS_LOGLEVEL 1



struct vpn_ws_var {
	char *key;
	uint16_t keylen;
	char *value;
	uint16_t vallen;
};
typedef struct vpn_ws_var vpn_ws_var;


struct vpn_ws_mac {
	uint8_t mac[6];
	struct vpn_ws_mac *next;
};

typedef struct vpn_ws_mac vpn_ws_mac;

struct vpn_ws_peer {
	int fd;
    int ping; // ping interval sec
    unsigned int timeout; // in ms

	uint8_t *buf;
	uint64_t pos;
	uint64_t len;

	uint8_t *write_buf;
    uint64_t write_pos;
    uint64_t write_len;

	uint16_t vars_n;
	vpn_ws_var vars[64];

	uint8_t handshake;
	uint8_t is_writing;

	uint8_t has_mask;
	uint8_t mask[4];

	uint8_t mac_collected;
	uint8_t mac[6];

	uint64_t rx;
	uint64_t tx;

	uint8_t raw;

	char *remote_addr;
	uint16_t remote_addr_len;
	char *remote_user;
	uint16_t remote_user_len;
	char *dn;
	uint16_t dn_len;

	time_t t;
	uint8_t bridge;
	vpn_ws_mac *macs;
	uint8_t ctrl;
};
typedef struct vpn_ws_peer vpn_ws_peer;

struct vpn_ws_config {
	char *server_addr;
	char *tuntap_name;

	char *uid;
	char *gid;

	char *exec;
	char *ssl_key;
	char *ssl_crt;

    int timeout; // sec, for reconnect
    int ping; // sec, ping interval

	int no_multicast;
	int no_broadcast;
	int bridge;
	int ssl_no_verify;
	int mtu;

	uint8_t tuntap_mac[6];

	// this is the highest fd used
	uint64_t peers_n;
	// this memory is dynamically increased
	vpn_ws_peer **peers;

	// used for ssl/tls context
	gnutls_session_t ssl_ctx;
} vpn_ws_conf;


typedef struct vpn_ws_config vpn_ws_config;

extern vpn_ws_config vpn_ws_conf;

void vpn_ws_error(char *);
void vpn_ws_exit(int);

int vpn_ws_bind(char *);

int vpn_ws_event_queue(int);
int vpn_ws_event_add_read(int, int);
int vpn_ws_event_wait(int, void *);
void *vpn_ws_event_events(int);
int vpn_ws_event_fd(void *, int);
int vpn_ws_event_read_to_write(int, int);
int vpn_ws_event_write_to_read(int, int);

int vpn_ws_tuntap(char *);

uint16_t vpn_ws_be16(uint8_t *);
uint64_t vpn_ws_be64(uint8_t *);
uint16_t vpn_ws_le16(uint8_t *);

int vpn_ws_peer_add_var(vpn_ws_peer *, char *, uint16_t, char *, uint16_t);

void *vpn_ws_malloc(uint64_t);
void *vpn_ws_calloc(uint64_t);
void vpn_ws_peer_destroy(vpn_ws_peer *);

void vpn_ws_peer_accept(int, int);

int vpn_ws_manage_fd(int, int);

int64_t vpn_ws_handshake(int, vpn_ws_peer *);
char *vpn_ws_peer_get_var(vpn_ws_peer *, char *, uint16_t, uint16_t *);

uint16_t vpn_ws_base64_encode(uint8_t *, uint16_t, uint8_t *);

int vpn_ws_read(vpn_ws_peer *, uint64_t);
int vpn_ws_write(vpn_ws_peer *, uint8_t *, uint64_t);
int vpn_ws_continue_write(vpn_ws_peer *);

int64_t vpn_ws_websocket_parse(vpn_ws_peer *, uint16_t *);

int vpn_ws_mac_is_broadcast(uint8_t *);
int vpn_ws_mac_is_zero(uint8_t *);
int vpn_ws_mac_is_valid(uint8_t *);
int vpn_ws_mac_is_loop(uint8_t *, uint8_t *);
int vpn_ws_mac_is_multicast(uint8_t *);

vpn_ws_peer *vpn_ws_peer_by_mac(uint8_t *);

int vpn_ws_nb(int);
void vpn_ws_peer_create(int, int, uint8_t *);

void vpn_ws_log(char *, ...);

gnutls_session_t vpn_ws_ssl_handshake(vpn_ws_peer *peer, char *sni, char *key, char *crt);
ssize_t vpn_ws_ssl_write(gnutls_session_t ctx, uint8_t *buf, size_t len);
ssize_t vpn_ws_ssl_read(gnutls_session_t session, uint8_t* buf, size_t len);
void vpn_ws_ssl_close(gnutls_session_t session, int sd);

int vpn_ws_exec(char *);
void vpn_ws_announce_peer(vpn_ws_peer *, char *);

int64_t vpn_ws_ctrl_json(int, vpn_ws_peer *);

int vpn_ws_str_to_uint(char *, uint64_t);
char *vpn_ws_strndup(char *, size_t);
int vpn_ws_is_a_number(char *);

int vpn_ws_bridge_collect_mac(vpn_ws_peer *, uint8_t *);

vpn_ws_peer * vpn_ws_peer_by_bridge_mac(uint8_t *);
