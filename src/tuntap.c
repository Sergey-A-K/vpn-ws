#include "vpn-ws.h"

#include <linux/if_tun.h>
#define TUNTAP_DEVICE "/dev/net/tun"

int vpn_ws_tuntap(char *name) {

    int fd = open(TUNTAP_DEVICE, O_RDWR);
	if (fd < 0) { vpn_ws_error("vpn_ws_tuntap()/open()"); return -1; }
    struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) { vpn_ws_error("vpn_ws_tuntap()/ioctl()"); return -1; }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)      { vpn_ws_error("vpn_ws_tuntap()/ioctl()"); return -1; }
	// copy MAC address
	memcpy(vpn_ws_conf.tuntap_mac, ifr.ifr_hwaddr.sa_data, 6);
	//printf("%x %x\n", vpn_ws_conf.tuntap_mac[0], vpn_ws_conf.tuntap_mac[1]);
	return fd;
}

/*
int vpn_ws_tuntap(char *name) {
	int fd = -1;
	fd = open(name, O_RDWR);
	if (fd < 0) {
		vpn_ws_error("vpn_ws_tuntap()/open()");
		return -1;
	}

	return fd;
}
*/
