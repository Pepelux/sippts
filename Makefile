prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_DIR ?= $(INSTALL) -d
INSTALL_DATA ?= $(INSTALL) -m 644

all:

install:
	$(INSTALL_DIR)					$(DESTDIR)/$(bindir)
	$(INSTALL_PROGRAM)	sipcracker.pl		$(DESTDIR)/$(bindir)/sipcracker
	$(INSTALL_PROGRAM)	sipdigestleak.pl	$(DESTDIR)/$(bindir)/sipdigestleak
	$(INSTALL_PROGRAM)	sipexten.pl		$(DESTDIR)/$(bindir)/sipexten
	$(INSTALL_PROGRAM)	sipinvite.pl		$(DESTDIR)/$(bindir)/sipinvite
	$(INSTALL_PROGRAM)	sipreport.pl		$(DESTDIR)/$(bindir)/sipreport
	$(INSTALL_PROGRAM)	sipscan.pl		$(DESTDIR)/$(bindir)/sipscan
	$(INSTALL_PROGRAM)	sipsniff.pl		$(DESTDIR)/$(bindir)/sipsniff
	$(INSTALL_PROGRAM)	sipspy.pl		$(DESTDIR)/$(bindir)/sipspy
