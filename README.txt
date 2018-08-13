==Suite of tools for penetration test over SIP protocol==

========
Download
========
https://github.com/Pepelux/sippts


Sippts is a suite of tools to audit VoIP servers and devices using SIP protocol. Sippts is programmed in Perl script and it consists of:

=======
Sipscan
=======
Fast scanner for SIP services that uses multithread. Sipscan can check IP and port ranges and works over UDP or TCP.

$ perl sipscan.pl 

SipSCAN - by Pepelux <pepeluxx@gmail.com>
-------

Usage: perl sipscan.pl -h <host> [options]
 
== Options ==
-m  <string>     = Method: REGISTER/INVITE/OPTIONS (default: OPTIONS)
-u  <string>     = Username
-s  <integer>    = Source number (CallerID) (default: 100)
-d  <integer>    = Destination number (default: 100)
-r  <integer>    = Remote port (default: 5060)
-proto <string>  = Protocol (udp, tcp or all (both of them) - By default: ALL)
-ip <string>     = Source IP (by default it is the same as host)
-ua <string>     = Customize the UserAgent
-db              = Save results into database (sippts.db)
-nolog           = Don't show anything on the console
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
 
== Examples ==
$perl sipscan.pl -h 192.168.0.1
	To search SIP services on 192.168.0.1 port 5060 (using OPTIONS method)
	To search several ranges
$perl sipscan.pl -h 192.168.0.1,192.168.2.0/24.192.168.3.1-192.168.20.200
	To search SIP services using INVITE method
$perl sipscan.pl -h 192.168.0.1 -m INVITE
	To search SIP services on 192.168.0.1 port 5060 (using INVITE method)
$perl sipscan.pl -h 192.168.0.0/24 -v -t tcp
	To search SIP services on 192.168.0.0 network by TCP connection (using OPTIONS method)
$perl sipscan.pl -h 192.168.0.1-192.168.0.100 -r 5060-5070 -vv
	To search SIP services on 192.168.0.100 ports from 5060 to 5070 (using OPTIONS method)


========
Sipexten
========
Identifies extensions on a SIP server. Sipexten uses multithread and can check IP and port ranges

$ perl sipexten.pl 

SipEXTEN - by Pepelux <pepeluxx@gmail.com>
--------

Usage: perl sipexten.pl -h <host> [options]
 
== Options ==
-e  <string>     = Extensions (default 100-300)
-s  <integer>    = Source number (CallerID) (default: 100)
-d  <integer>    = Destination number (default: 100)
-r  <integer>    = Remote port (default: 5060)
-p  <string>     = Prefix (for extensions)
-proto <string>  = Protocol (udp, tcp or all (both of them) - By default: ALL)
-ip <string>     = Source IP (by default it is the same as host)
-ua <string>     = Customize the UserAgent
-db              = Save results into database (sippts.db)
-nolog           = Don't show anything on the console
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
 
== Examples ==
$perl sipexten.pl -h 192.168.0.1 -e 100-200 -v
	To check extensions range from 100 to 200 (with verbose mode)
$perl sipexten.pl -h 192.168.0.1 -e 100-200 -v
	To check several ranges
$perl sipexten.pl -h 192.168.0.1,192.168.2.0/24.192.168.3.1-192.168.50.200
	To check extensions range from user100 to user200
$perl sipexten.pl -h 192.168.0.0/24 -e 100 -r 5060-5080 -vv
	To check extension 100 with destination port between 5060 and 5080 (with packages info)


========
Sipcrack
========
Remote password cracker. Sipcrack uses multithread and can test passwords for several users in IP and port ranges

$ perl sipcrack.pl

SipCRACK - by Pepelux <pepeluxx@gmail.com>
--------

Usage: perl sipcrack.pl -h <host> -w wordlist [options]
 
== Options ==
-e  <string>     = Extension (default from 100 to 1000)
-s  <integer>    = Source number (CallerID) (default: 100)
-d  <integer>    = Destination number (default: 100)
-r  <integer>    = Remote port (default: 5060)
-p  <string>     = Prefix (for extensions)
-proto <string>  = Protocol (udp or tcp - By default: udp)
-ip <string>     = Source IP (by default it is the same as host)
-ua <string>     = Customize the UserAgent
-db              = Save results into database (sippts.db)
-resume          = Resume last session
-w               = Wordlist
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
 
== Examples ==
$perl sipcrack.pl -h 192.168.0.1 -w wordlist
	Try to crack extensions from 100 to 1000 on 192.168.0.1 port 5060
$perl sipcrack.pl -h 192.168.0.0/24 -e 100-200 -p user -w wordlist -v
	Try to crack extensions from user100 to user200 on 192.168.0.0 network


=========
Sipinvite
=========
Check if a server allow us to make calls without authentication. If the SIP server has a bad configuration, it will allows us to make calls to external numbers. Also it can allow us to transfer the call to a second external number

$ perl sipinvite.pl 

SipINVITE - by Pepelux <pepeluxx@gmail.com>
---------

Usage: perl sipinvite.pl -h <host> -d <dst_number> [options]
 
== Options ==
-d  <integer>    = Destination number
-u  <string>     = Username to authenticate
-p  <string>     = Password to authenticate
-s  <integer>    = Source number (CallerID) (default: 100)
-l  <integer>    = Local port (default: 5070)
-r  <integer>    = Remote port (default: 5060)
-t  <integer>    = Transfer call to another number
-ip <string>     = Source IP (by default it is the same as host)
-ua <string>     = Customize the UserAgent
-v               = Verbose (trace information)
 
== Examples ==
$perl sipinvite.pl -h 192.168.0.1 -d 100
	Trying to make a call to exten 100 (without auth)
$perl sipinvite.pl -h 192.168.0.1 -u sipuser -p supersecret -d 100 -r 5080
	Trying to make a call to exten 100 (with auth)
$perl sipinvite.pl -h 192.168.0.1 -s 200 -d 555555555 -v
	Trying to make a call to number 555555555 (without auth) with source number 200
$perl sipinvite.pl -h 192.168.0.1 -d 555555555 -t 666666666
	Trying to make a call to number 555555555 (without auth) and transfer it to number 666666666
$perl sipinvite.pl -h 192.168.0.1 -d 555555555 -t 666666666 -s 123456789
	Trying to make a call to number 555555555 (without auth) using callerid 123456789 and transfer it to number 666666666


========
Sipsniff
========
Simple sniffer for SIP protocol that allows us to filter by SIP method type

$ perl sipsniff.pl 

SipSNIFF - by Pepelux <pepeluxx@gmail.com>
--------

Usage: sudo perl -i <interface> sipsniff.pl [options]
 
== Options ==
-i  <string>     = Interface (ex: eth0)
-p  <integer>    = Port (default: 5060)
-m  <string>     = Filter method (ex: INVITE, REGISTER)
-u               = Filter authentication digest

== Examples ==
$sudo perl sipsniff.pl -i eth0
$sudo perl sipsniff.pl -i eth0 -m INVITE
$sudo perl sipsniff.pl -i eth0 -u

======
Sipbye
======
Send BYE message to end a call

$ perl sipbye.pl 

SipBYE - by Pepelux <pepeluxx@gmail.com>
------

Usage: perl sipbye.pl -h <host> -p <port> -c <callid> [options]
 
== Options ==
-p  <integer>    = Remote port
-c  <string>     = Call-ID
-ua <string>     = Customize the UserAgent
-v               = Verbose (trace information)
 
== Examples ==
\$perl sipbye.pl -h 192.168.0.1 -p 5060

======
Sipspy
======
Simple sip server that show us digest auth requests and responses. Example:

[=>] 192.168.1.129:43455 REGISTER
     [ Sending digest => WWW-Authenticate: Digest algorithm=MD5, realm="asterisk", nonce="405a7bc0" ]
[=>] 192.168.1.129:43455 REGISTER
     [ Digest response => Authorization: Digest username="200", realm="asterisk", nonce="405a7bc0", uri="sip:201@192.168.1.129", response="e270e69d53011d2f1219b6dfe018743d", algorithm=MD5 ]

$ perl sipspy.pl -h

SipSPY - by Pepelux <pepeluxx@gmail.com>
--------

Usage: sudo perl sipspy.pl [options]
 
== Options ==
-p  <integer>    = Port (default: 5060)
-v               = Verbose

==Operating System==
Sippts was tested on:
* Linux
* Mac OS X
* Windows

==Requirements==
* Perl

sudo apt-get install libnet-pcap-perl libio-socket-ip-perl libsocket-perl libnetaddr-ip-perl libdbd-sqlite3-perl
sudo cpan -i IO:Socket:Timeout
sudo cpan -i String:HexConvert

