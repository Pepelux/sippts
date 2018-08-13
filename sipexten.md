Sipexten identifies extensions on a SIP server. Sipexten uses multithread and can check large network and port ranges.

# Features #
Sipexten allows us to:

  * Identify extensions on a SIP server.
  * Scan for large ranges of extensions.
  * Connect over UDP or TCP protocol.
  * Try UDP and TCP at the same time.
  * Analyze responses using verbose mode.

# Usage #
```
$ perl sipexten.pl 

SipEXTEN - by Pepelux <pepeluxx@gmail.com>
--------

Usage: perl sipexten.pl -h <host> [options]
 
== Options ==
-e  <string>     = Extensions (default 100-1000)
-s  <integer>    = Source number (CallerID) (default: 100)
-d  <integer>    = Destination number (default: 100)
-r  <integer>    = Remote port (default: 5060)
-p  <string>     = Prefix (for extensions)
-proto  <string>  = Protocol (UDP or TCP - By default: UDP)
-ip <string>     = Source IP (by default it is the same as host)
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
```

  * Search for extension range on a specific server
```
$perl sipexten.pl -h 192.168.0.1 -e 100-200
```
  * Search extensions from 100 to 2000 on a network range with destination port between 5060 and 5080
```
$perl sipexten.pl -h 192.168.0.0/24 -e 100-2000 -r 5060-5080
```

# Example #
```
$ perl sipexten.pl -h 192.168.0.55 -e 100-200
^C
IP address	Port	Extension	Authentication
==========	====	=========	==============
192.168.0.55	5060	100		No authentication required
192.168.0.55	5060	101		Require authentication
```
