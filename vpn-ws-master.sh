# -14 MTU
./vpn-ws-client tun1 wss://hostname/vws --mtu 1472   --exec "ifconfig tun1 10.10.0.2 netmask 255.255.255.0 mtu 1458"
