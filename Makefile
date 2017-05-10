KVER   ?= $(shell uname -r)
KDIR   ?= /lib/modules/$(KVER)/build/
DEPMOD  = /sbin/depmod -a
CC     ?= gcc
XFLAGS ?= $(shell pkg-config xtables --cflags 2>/dev/null)
obj-m   = xt_ratelimit.o
CFLAGS_xt_ratelimit.o := -DDEBUG

all: xt_ratelimit.ko libxt_ratelimit.so

xt_ratelimit.ko: version.h xt_ratelimit.c xt_ratelimit.h compat.h
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y
	-sync

%_sh.o: libxt_ratelimit.c xt_ratelimit.h
	gcc -O2 -Wall -Wunused -fPIC ${XFLAGS} ${CFLAGS} -o $@ -c $<

%.so: %_sh.o
	gcc -shared -o $@ $<

sparse: clean | version.h xt_ratelimit.c xt_ratelimit.h compat.h
	make -C $(KDIR) M=$(CURDIR) modules C=1

cppcheck:
	cppcheck -I $(KDIR)/include --enable=all --inconclusive xt_ratelimit.c
	cppcheck libxt_ratelimit.c

coverity:
	coverity-submit -v

version.h: xt_ratelimit.c xt_ratelimit.h compat.h Makefile
	@./version.sh --define > version.h

clean:
	-make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *_sh.o *.o modules.order

install: | minstall linstall

minstall: | xt_ratelimit.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

linstall: libxt_ratelimit.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

uninstall:
	-rm -f $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/libxt_ratelimit.so
	-rm -f $(KDIR)/extra/xt_ratelimit.ko

load: all
	-sync
	-modprobe x_tables
	-insmod ./xt_ratelimit.ko
	-iptables  -I INPUT  -m ratelimit --ratelimit-set src --ratelimit-mode src -j DROP
	-iptables  -I OUTPUT -m ratelimit --ratelimit-set dst --ratelimit-mode dst -j DROP
	-ip6tables -I OUTPUT -m ratelimit --ratelimit-set dst --ratelimit-mode dst -j DROP
	-echo +127.0.0.1 1000000 > /proc/net/ipt_ratelimit/src
	-echo +127.0.0.1/24 1000000 > /proc/net/ipt_ratelimit/dst
	-echo +127.2.0.1/16 1000000 > /proc/net/ipt_ratelimit/dst
	-echo +127.0.0.1/8 1000000 > /proc/net/ipt_ratelimit/dst
	-echo +::1 1000000 > /proc/net/ipt_ratelimit/dst
unload:
	-echo / > /proc/net/ipt_ratelimit/src
	-iptables  -D INPUT  -m ratelimit --ratelimit-set src --ratelimit-mode src -j DROP
	-iptables  -D OUTPUT -m ratelimit --ratelimit-set dst --ratelimit-mode dst -j DROP
	-ip6tables -D OUTPUT -m ratelimit --ratelimit-set dst --ratelimit-mode dst -j DROP
	-rmmod xt_ratelimit.ko
del:
	-sync
	-echo -127.0.0.1 1000000 > /proc/net/ipt_ratelimit/dst
reload: unload load

.PHONY: all minstall linstall install uninstall clean cppcheck
