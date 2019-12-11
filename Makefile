INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DIR = $(INSTALL) -d
INSTALL_DATA = $(INSTALL) -m 644

all:

install:
	$(INSTALL_DIR)					$(DESTDIR)/usr/bin
	$(INSTALL_PROGRAM)	sipcracker.pl		$(DESTDIR)/usr/bin/sipcracker
	$(INSTALL_PROGRAM)	sipdigestleak.pl	$(DESTDIR)/usr/bin/sipdigestleak
	$(INSTALL_PROGRAM)	sipexten.pl		$(DESTDIR)/usr/bin/sipexten
	$(INSTALL_PROGRAM)	sipinvite.pl		$(DESTDIR)/usr/bin/sipinvite
	$(INSTALL_PROGRAM)	sipreport.pl		$(DESTDIR)/usr/bin/sipreport
	$(INSTALL_PROGRAM)	sipscan.pl		$(DESTDIR)/usr/bin/sipscan
	$(INSTALL_PROGRAM)	sipsniff.pl		$(DESTDIR)/usr/bin/sipsniff
	$(INSTALL_PROGRAM)	sipspy.pl		$(DESTDIR)/usr/bin/sipspy
