# What is Sippts? #

Sippts is a set of tools to audit VoIP servers and devices using SIP protocol. Sippts is programmed in Perl script and it allows us to check the security of a VoIP server using SIP protocol.

# Is it free? #

Yes. You can freely use, modify and distribute. If modified, please put a reference to this site.

# Can be use sippts for illegal purposes? #

Most security tools can be used for illegal purposes, but the finality of this tool is to check security of your own servers and not to use to do bad purposes. I am not responsible for the misuse of this tool.

# Set of tools for penetration test over SIP protocol #

Sippts is a set of tools to audit VoIP servers and devices using SIP protocol. Sippts is programmed in Perl script and the tools are:
  * _**Sipscan**_ is a fast scanner for SIP services that uses multithread. Sipscan can check several IPs and port ranges and it can work over UDP or TCP.

[Click here to read more about SIPscan](https://github.com/Pepelux/sippts/wiki/SIPscan)

  * _**Sipexten**_ identifies extensions on a SIP server. Also tells you if the extension line requires authentication or not. Sipexten can check several IPs and port ranges.

[Click here to read more about SIPexten](https://github.com/Pepelux/sippts/wiki/SIPexten)

  * _**Sipcrack**_ is a remote password cracker. Sipcrack can test passwords for several users in different IPs and port ranges.

[Click here to read more about SIPcrack](https://github.com/Pepelux/sippts/wiki/SIPcrack)

  * _**Sipinvite**_ checks if a server allow us to make calls without authentication. If the SIP server has a bad configuration, it will allow us to make calls to external numbers. Also it can allow us to transfer the call to a second external number.

[Click here to read more about SIPinvite](https://github.com/Pepelux/sippts/wiki/SIPinvite)

  * _**Sipsniff**_ is a simple sniffer for SIP protocol that allows us to filter by SIP method type.

[Click here to read more about SIPsniff](https://github.com/Pepelux/sippts/wiki/SIPsniff)

  * _**Sipspy**_ is a simple sip server that show us digest auth requests and responses.

[Click here to read more about SIPspy](https://github.com/Pepelux/sippts/wiki/SIPspy)

## Operating System ##
Sippts has been tested on:
  * Linux
  * Mac OS X
  * Windows

## Requirements ##
  * Perl

And install next modules:
  * cpan -i IO:Socket:Timeout
  * cpan -i NetAddr:IP
  * cpan -i String:HexConvert
