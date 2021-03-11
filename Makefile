target=tcap
source=main.c
libs+= -lpcap
prefix=/usr/local/bin
all: tcap_debug

tcap_debug:
	gcc $(source) -O2 -DDEBUG $(libs) -g -o $(target)
tcap_daemon:
	gcc $(source) -O2 -DDAEMON $(libs) -o $(target)
tcap:
	gcc $(source) -O2 $(libs) -o $(target)
install: tcap
	install -p -m 0755 tcap $(prefix)
install_daemon: tcap_daemon
	install -p -m 0644 tcap.service /lib/systemd/system
