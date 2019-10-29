INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DIR = $(INSTALL) -d
INSTALL_DATA = $(INSTALL) -m 644

all:

install:
	$(INSTALL_DIR)					$(DEST_DIR)/usr/bin
	$(INSTALL_PROGRAM)	sipcrack.pl		$(DEST_DIR)/usr/bin/sipcrack
	$(INSTALL_PROGRAM)	sipdigestleak.pl	$(DEST_DIR)/usr/bin/sipdigestleak
	$(INSTALL_PROGRAM)	sipexten.pl		$(DEST_DIR)/usr/bin/sipexten
	$(INSTALL_PROGRAM)	sipinvite.pl		$(DEST_DIR)/usr/bin/sipinvite
	$(INSTALL_PROGRAM)	sipreport.pl		$(DEST_DIR)/usr/bin/sipreport
	$(INSTALL_PROGRAM)	sipscan.pl		$(DEST_DIR)/usr/bin/sipscan
	$(INSTALL_PROGRAM)	sipsniff.pl		$(DEST_DIR)/usr/bin/sipsniff
	$(INSTALL_PROGRAM)	sipspy.pl		$(DEST_DIR)/usr/bin/sipspy
