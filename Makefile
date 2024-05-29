MAKE = make

all: backdoor rootkit

backdoor:
	$(MAKE) -f Makefile.backdoor

rootkit:
	$(MAKE) -f Makefile.rootkit

install:
	$(MAKE) -f Makefile.backdoor install
	$(MAKE) -f Makefile.rootkit install

uninstall:
	$(MAKE) -f Makefile.rootkit uninstall
	$(MAKE) -f Makefile.backdoor uninstall

clean:
	$(MAKE) -f Makefile.backdoor clean
	$(MAKE) -f Makefile.rootkit clean

.PHONY: all backdoor rootkit install uninstall clean

