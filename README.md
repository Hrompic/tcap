# tcap
Tcap Sniffer

Use make&&./tcap to run
tcap :
Usage: start (packets are being sniffed from now on from default iface(eth0))
stop (packets are not sniffed)
show [ip] count (print number of packets received from ip address)
select iface [iface] (select interface for sniffing eth0, wlan0, ethN, wlanN...)
stat [iface] show all collected statistics for particular interface, if iface omitted - for all interfaces.
--help (show usage information)

Make as deamon:
make_install_daemon

Install:
make install 
