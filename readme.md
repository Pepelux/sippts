![logo](http://blog.pepelux.org/wp-content/uploads/logo-de-sippts.png)


# What is Sippts? #

Sippts is a set of tools to audit VoIP servers and devices using SIP protocol. Sippts is programmed in Perl script and it allows us to check the security of a VoIP server using SIP protocol.

# Is it free? #

Yes. You can freely use, modify and distribute. If modified, please put a reference to this site.

# Can be use sippts for illegal purposes? #

Most security tools can be used for illegal purposes, but the purpose of this tool is to check the security of your own servers and not to use to do bad things. I am not responsible for the misuse of this tool.

# Set of tools for penetration test over SIP protocol #

Sippts is a set of tools to audit VoIP servers and devices using SIP protocol. Sippts is programmed in Perl script and the tools are:
  * _**Sipscan**_ is a fast scanner for SIP services that uses multithread. Sipscan can check several IPs and port ranges and it can work over UDP or TCP.

[Click here to read more about SIPscan](https://github.com/Pepelux/sippts/wiki/SIPscan)

  * _**Sipexten**_ identifies extensions on a SIP server. Also tells you if the extension line requires authentication or not. Sipexten can check several IPs and port ranges.

[Click here to read more about SIPexten](https://github.com/Pepelux/sippts/wiki/SIPexten)

  * _**Siprcrack**_ is a remote password cracker. Siprcrack can test passwords for several users in different IPs and port ranges.

[Click here to read more about SIPRcrack](https://github.com/Pepelux/sippts/wiki/SIPRCrack)

  * _**Sipinvite**_ checks if a server allow us to make calls without authentication. If the SIP server has a bad configuration, it will allow us to make calls to external numbers. Also it can allow us to transfer the call to a second external number.

[Click here to read more about SIPinvite](https://github.com/Pepelux/sippts/wiki/SIPinvite)

  * _**SipDigestLeak**_ Exploits the SIP digest leak vulnerability discovered by Sandro Gauci that affects a large number of hardware and software devices.

[Click here to read more about SIPDigestLeak](https://github.com/Pepelux/sippts/wiki/SIPDigestLeak)

  * _**SipFlood**_ Send unlimited messages to the target.

[Click here to read more about SIPFlood](https://github.com/Pepelux/sippts/wiki/SIPFlood)

  * _**SipSend**_ Allow us to send a customized SIP message and analyze the response.

[Click here to read more about SIPSend](https://github.com/Pepelux/sippts/wiki/SIPSend)

  * _**SipEnumerate**_ Enumerate available methods of a SIP service/server.

[Click here to read more about SIPEnumerate](https://github.com/Pepelux/sippts/wiki/SIPEnumerate)

  * _**SipDump**_ Extracts SIP Digest authentications from a PCAP file.

[Click here to read more about SIPDump](https://github.com/Pepelux/sippts/wiki/SIPDump)

  * _**SipCrack**_ Cracking tool to crack the digest authentications within the SIP protocol.

[Click here to read more about SIPCrack](https://github.com/Pepelux/sippts/wiki/SIPCrack)

## Operating System ##
Sippts has been tested on:
  * Linux
  * Mac OS X
  * Windows

## Requirements ##
  * Python 3
  
## Instalation & Usage ##
  * Clone or download the repository
  * pip3 install -r requirements.txt
  * Enjoy
