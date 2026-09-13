![logo](http://blog.pepelux.org/wp-content/uploads/logo-de-sippts.png)


# What is Sippts? #

Sippts is a set of tools to audit VoIP servers and devices using the SIP protocol. Sippts is programmed in Python and it allows us to check the security of a VoIP server using the SIP protocol.

# Is it free? #

Yes. You can freely use, modify and distribute it. If you modify it, please include a reference to this site.

# Can sippts be used for illegal purposes? #

The purpose of this tool is to audit your own systems or to perform penetration tests on systems for which you have received express authorisation. I am not responsible for the misuse of this tool.

# Usage #

Show help:

```
sippts -h
usage: sippts [-h] [-up] {video,astami,scan,exten,rcrack,send,wssend,enumerate,leak,ping,invite,dump,dcrack,flood,sniff,spoof,pcapdump,rtpbleed,rtcpbleed,rtpbleedflood,rtpbleedinject} ...


⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠤⠶⠒⠛⠉⠉⠉⠉⠀⠀⢀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣬⣍⣙⣳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠴⠒⠋⠉⠀⠀⠀⢀⣀⣠⡤⠴⠖⠚⠛⠉⠉⠉⠀⣠⡶⠖⠲⣄⠀⠀⠀⠀⠀⠀⠀⠈⠉⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡤⠖⠋⠁⠀⠀⠀⣀⣤⠴⠖⣛⣉⣁⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⡇⢹⡄⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⡤⠞⠋⠀⠀⠀⢀⣠⠴⠚⠋⠁⠀⠀⡿⡏⠀⠈⣧⣤⠴⠖⠚⠛⠉⠉⠳⢄⡀⠀⣧⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⡞⠧⣄⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⢀⣴⠇⢹⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠉⣲⣿⣀⣠⣼⣦⣤⣀⣀⣀⡀⠀⢀⣀⣠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡿⠀⠀⠈⣿⠉⠀⠀⠀⠀⠀⠀⠙⢄⣰⠏⠀⠀⠘⡇⠀⠀⣇⢀⣀⡤⠤⠖⠒⠛⠉⠉⠉⣁⣀⠀⠀⠀⠉⠙⠛⢿⣿⡛⠛⠛⢻⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣸⣧⣄⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⡄⠀⠀⠀⣷⠴⠚⠋⠉⠀⠀⢀⣠⣴⡖⠛⠉⠿⢻⣿⣉⡉⠙⠓⢲⠦⢤⣈⠙⢶⣶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣏⠙⢦⣹⣼⠀⠀⠀⠀⠀⠀⢀⣴⣾⠟⠁⢀⡏⢀⡞⠀⠀⠀⠀⠀⣰⣯⡟⡀⠀⣼⡏⢘⡢⢠⣷⣾⡿⠿⠿⣷⣤⣞⠀⠙⢦⡀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⡟⠿⡍⢷⢀⡇⠀⠀⠀⠀⠀⠀⠀⣠⣾⠏⣧⠀⢀⡞⠁⠀⠀⠀⠀⢠⡴⠋⠛⠻⣧⣤⡶⢿⡹⡟⠛⢯⣉⣿⢾⣧⣄⡈⠙⠲⢝⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣏⠙⢦⣹⣼⠀⠀⠀⠀⠀⠀⢀⣴⣾⠟⠁⢀⡏⢀⡞⠀⠀⠀⠀⠀⣰⣯⡟⡀⠀⣼⡏⢘⡢⢠⣷⣾⡿⠿⠿⣷⣤⣞⠀⠙⢦⡀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                     SIPPTS version 4.1.2 (updated)
⣿⣍⡓⣄⣿⣧⣤⣤⣤⣶⣶⠿⠟⠋⠀⠀⣠⣎⣠⠎⠘⢄⠀⠀⠀⢀⡏⠛⠙⠋⢸⠋⠧⠤⠗⣾⢻⠁⠀⠀⠀⠀⠈⠻⡳⡀⠀⠙⢦⠀⣠⡹⡟⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀                          CVE version 0.1 (updated)
⣷⣤⣙⢾⣿⣭⡉⠉⠉⠁⠀⠀⣀⣠⠴⠚⠉⠉⠀⠀⠀⠈⠳⡀⠀⠘⣧⣤⢀⠀⢸⡶⣏⠙⣦⠹⡜⢦⡀⠀⠀⠀⠀⢀⡇⣿⣶⣶⣾⣿⣥⡇⠹⡌⠻⣄⠀⠀⠀⠀⠀⠀⠀⠀        https://github.com/Pepelux/sippts
⣿⠤⢬⣿⣇⠈⢹⡟⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢆⠀⢻⡹⡎⠃⠀⠳⡄⣽⠛⠦⠉⠲⣍⣓⣒⢒⣒⣉⡴⠋⣟⠙⢲⣿⠘⠃⠀⣷⠀⠙⢧⡀⠀⠀⠀⠀⠀⠀by Pepelux - https://twitter.com/pepeluxx
⣿⠶⠒⠺⣿⡀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢣⡀⠳⡄⢀⡀⠀⠙⠮⣗⠚⢠⡖⠲⣌⣉⡭⣍⡡⣞⠓⣾⠉⣽⠃⢠⡄⣼⣿⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀
⠸⡟⠉⣉⣻⣧⣼⠿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠙⢮⡿⢿⡃⠀⠈⠑⠶⢽⣒⣃⣘⣲⣤⣗⣈⣹⠵⠛⠁⠀⠀⡴⣻⠃⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀
⠀⠹⣯⣁⣠⠼⠿⣿⡲⠿⠷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠙⠳⣄⡀⠀⣄⣶⣄⠀⠉⠉⠉⣉⡉⠉⠀⠀⠘⣶⣴⣦⠞⠁⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀
⠀⠀⠘⣧⡤⠖⢋⣩⠿⣶⣤⣈⣙⣷⣤⣀⣠⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⡀⠀⠀⠉⠓⠶⢽⣼⣆⡀⠀⠀⢿⣿⣶⣀⣀⡬⠷⠚⠁⣀⣀⣀⠀⢰⣿⠿⡇⠀⠘⣧⠀⠀
⠀⠀⠀⠀⠙⠾⣏⣤⠞⢁⡞⠉⣿⠋⣹⠉⢹⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠀⣤⣤⣄⠀⣿⠙⢻⠆⠀⠓⢒⣁⡤⠴⠺⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠒⠻⠤⣴⣇⣀⣿⣀⣾⡤⠿⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⣀⣀⡀⠀⢸⠿⢷⡄⠀⣿⣀⡿⠀⢈⣉⡭⠴⠒⠋⠉⠀⠀⠀⠀⢻⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠰⣟⠛⡇⠀⠘⠧⠞⢁⣀⡤⠴⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣼⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣦⣀⠀⠀⠀⠀⠀⠀⠈⢧⠀⠀⠀⠉⢋⣁⡤⠴⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣴⠶⠚⠛⠉⢉⣽⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⡀⠀⠀⠀⠀⠘⡆⠴⠒⠋⠉⠀⠀      ⢀⣀⣤⠴⠖⠛⠉⠉⠉⠉⠙⠛⠋⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢛⠷⠦⠀⠀⠀⣿⠀⠀   ⠀⠀⠀⢠⠴⡖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
              ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣤⡀⠀⠘⡆⠴⠒⠋⠉⣤⠴⠖⠛⠀⠀
            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢛⢠⠴⡖⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

 -= SIPPTS is a set of tools for auditing VoIP systems based on the SIP protocol =-

Commands:
  {video,astami,scan,exten,rcrack,send,wssend,enumerate,leak,ping,invite,dump,dcrack,flood,sniff,spoof,pcapdump,rtpbleed,rtcpbleed,rtpbleedflood,rtpbleedinject}
    video                                         Animated help
    astami                                        Asterisk AMI pentest
    scan                                          Fast SIP scanner
    exten                                         Search SIP extensions of a PBX
    rcrack                                        Remote password cracker
    send                                          Send a customized message
    wssend                                        Send a customized message over WS
    enumerate                                     Enumerate methods of a SIP server
    leak                                          Exploit SIP Digest Leak vulnerability
    ping                                          SIP ping
    invite                                        Try to make calls through a PBX
    dump                                          Dump SIP digest authentications from a PCAP file
    dcrack                                        SIP digest authentication cracking
    flood                                         Flood a SIP server
    sniff                                         SIP network sniffing
    spoof                                         ARP Spoofing tool
    pcapdump                                      Extract data from a PCAP file
    rtpbleed                                      Detect RTPBleed vulnerability (send RTP streams)
    rtcpbleed                                     Detect RTPBleed vulnerability (send RTCP streams)
    rtpbleedflood                                 Exploit RTPBleed vulnerability (flood RTP)
    rtpbleedinject                                Exploit RTPBleed vulnerability (inject WAV file)

Options:
  -h, --help                                      show this help message and exit
  -up                                             Update scripts

Command help:
  sippts <command> -h
```
Show help for command scan:

```
sippts scan -h
usage: sippts scan [-i IP|HOST] [-f FILE] [-r REMOTE_PORT] [-p PROTOCOL]
                   [-proxy IP:PORT] [-m METHOD] [-d DOMAIN]
                   [-cd CONTACT_DOMAIN] [-fn FROM_NAME] [-fu FROM_USER]
                   [-fd FROM_DOMAIN] [-tn TO_NAME] [-tu TO_USER]
                   [-td TO_DOMAIN] [-ua USER_AGENT] [-ppi PPI] [-pai PAI] [-v]
                   [-vv] [-nocolor] [-o FILE] [-oi FILE] [-ot FILE] [-oj FILE]
                   [-ocsv FILE] [-cve] [-th THREADS] [-t TIMEOUT] [-ping]
                   [-fp] [-random] [-local-ip IP] [-h]


  ___ ___ ___ ___ _____ ___                    
 / __|_ _| _ \ _ \_   _/ __|  ___ __ __ _ _ _  
 \__ \| ||  _/  _/ | | \__ \ (_-</ _/ _` | ' \ 
 |___/___|_| |_|   |_| |___/ /__/\__\__,_|_||_|
            
  Module scan is a fast SIP scanner using multithread that can check several IPs and port ranges. It works with UDP, TCP and TLS protocols.

Target:
  -i IP|HOST            Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24)
  -f FILE               File with several IPs or network ranges
  -r REMOTE_PORT        Ports to scan. Ex: 5060 | 5070,5080 | 5060-5080 | 5060,5062,5070-5080 | ALL for 1-65535 (default: 5060)
  -p, --protocol PROTOCOL
                        Protocol: udp|tcp|tls|all (default: udp)
  -proxy IP:PORT        Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)

Headers:
  -m METHOD             SIP method: options, invite, register (default: options)
  -d, --domain DOMAIN   SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)
  -cd CONTACT_DOMAIN    Domain or IP address for Contact header. Ex: 10.0.1.2
  -fn FROM_NAME         From Name. Ex: Bob
  -fu FROM_USER         From User (default: 100)
  -fd FROM_DOMAIN       From Domain. Ex: 10.0.0.1
  -tn TO_NAME           To Name. Ex: Alice
  -tu TO_USER           To User (default: 100)
  -td TO_DOMAIN         To Domain. Ex: 10.0.0.1
  -ua USER_AGENT        User-Agent header (default: pplsip)
  -ppi PPI              P-Preferred-Identity
  -pai PAI              P-Asserted-Identity

Log:
  -v                    Increase verbosity
  -vv                   Increase more verbosity
  -nocolor              Show result without colors
  -o FILE               Save data into a log file
  -oi FILE              Save IPs into a log file
  -ot FILE              Save found hosts as ip:port/proto, ready for -f of exten, rcrack and leak
  -oj FILE              Save results into a JSON file
  -ocsv FILE            Save results into a CSV file
  -cve                  Show possible CVEs

Other options:
  -th THREADS           Number of threads (default: 200)
  -t, --timeout TIMEOUT
                        Sockets timeout (default: 5)
  -ping                 Ping host before scan
  -fp                   Try to fingerprinting
  -random               Randomize target hosts
  -local-ip IP          Set local IP address (by default try to get it)
  -h, --help            Show this help

Usage examples:
  Searching for SIP services and devices with default ports (5060/udp) on the local network
     sippts scan -i 192.168.0.0/24
  Extend the port range from 5060 to 5080 and look for UDP, TCP and TLS services
     sippts scan -i 192.168.0.0/24 -r 5060-5080 -p all
  Load several target IP addresses from a file
     sippts scan -f targets.txt
  Random scanning for non-sequential scanning of IP ranges
     sippts scan -f targets.txt -random
  Disguise the tool behind another User-Agent
     sippts scan -i 192.168.0.0/24 -ua Grandstream
  Scan all ports and protocols of an address range using 500 threads (slow)
     sippts scan -f targets.txt -r all -p all -th 500 -ua Grandstream
  Typical scanning for large ranges
     sippts scan -f targets.txt -r 5060-5080 -p all -th 500 -ua Grandstream -v -fp -o output.txt
  Save the hosts found as ip:port/proto, to chain with exten, rcrack or leak
     sippts scan -i 192.168.0.0/24 -r 5060-5080 -p all -ot targets.txt
     sippts exten -f targets.txt -e 100-200 -oe extens.txt
     sippts rcrack -f targets.txt -ef extens.txt -w wordlist.txt
  Save the results as JSON or CSV, to process them with another tool
     sippts scan -i 192.168.0.0/24 -oj result.json -ocsv result.csv
```
Update scripts:

```
sippts -up
```

# Set of tools for penetration test over SIP protocol #

You can get help on how to use this tool at https://sippts.seguridadvoip.com and also on the Github wiki pages:

Sippts is a set of tools for auditing VoIP servers and devices using the SIP protocol. Sippts is programmed in Python and consists of the following commands or modules:
  * _**scan**_ is a fast multithreaded scanner for SIP services. It can check several IP addresses and port ranges, and it works over UDP, TCP and TLS. [Click here to read more about scan command](https://github.com/Pepelux/sippts/wiki/Command-scan)

  * _**exten**_ identifies extensions on a SIP server. It also tells you whether the extension requires authentication. It can check several IP addresses, and with -f it reads the targets from a file. [Click here to read more about exten command](https://github.com/Pepelux/sippts/wiki/Command-exten)

  * _**rcrack**_ is a remote password cracker. It can test passwords for several users on several IP addresses, and with -f it reads the targets from a file. [Click here to read more about rcrack command](https://github.com/Pepelux/sippts/wiki/Command-rcrack)

  * _**invite**_ checks whether a server allows us to make calls without authentication. If the SIP server has a bad configuration, it will allow us to make calls to external numbers. It can also transfer the call to a second external number. [Click here to read more about invite command](https://github.com/Pepelux/sippts/wiki/Command-invite)

  * _**leak**_ exploits the SIP Digest Leak vulnerability discovered by Sandro Gauci, which affects a large number of hardware and software devices. [Click here to read more about leak command](https://github.com/Pepelux/sippts/wiki/Command-leak)

  * _**flood**_ sends unlimited messages to the target. [Click here to read more about flood command](https://github.com/Pepelux/sippts/wiki/Command-flood)

  * _**send**_ sends a customized SIP message and analyzes the response. [Click here to read more about send command](https://github.com/Pepelux/sippts/wiki/Command-send)

  * _**wssend**_ sends a customized SIP message over WebSockets and analyzes the response. [Click here to read more about wssend command](https://github.com/Pepelux/sippts/wiki/Command-wssend)

  * _**enumerate**_ enumerates the available methods of a SIP service or server. [Click here to read more about enumerate command](https://github.com/Pepelux/sippts/wiki/Command-enumerate)

  * _**dump**_ extracts SIP Digest authentications from a PCAP file. [Click here to read more about dump command](https://github.com/Pepelux/sippts/wiki/Command-dump)

  * _**dcrack**_ cracks the digest authentications of the SIP protocol. [Click here to read more about dcrack command](https://github.com/Pepelux/sippts/wiki/Command-dcrack)

  * _**pcapdump**_ extracts SIP and RTP data from a PCAP file, and can save the audio streams as WAV files. [Click here to read more about pcapdump command](https://github.com/Pepelux/sippts/wiki/Command-pcapdump)

  * _**ping**_ sends a SIP ping to check whether a server or device is alive. [Click here to read more about ping command](https://github.com/Pepelux/sippts/wiki/Command-ping)

  * _**astami**_ scans and audits the Asterisk Manager Interface (AMI), and can run a command on the ones where the credentials work. [Click here to read more about astami command](https://github.com/Pepelux/sippts/wiki/Command-astami)

  * _**sniff**_ captures SIP traffic live and shows the messages, the devices and the digest authentications it sees. [Click here to read more about sniff command](https://github.com/Pepelux/sippts/wiki/Command-sniff)

  * _**spoof**_ is an ARP spoofing tool, to place yourself between two devices and capture their traffic. [Click here to read more about spoof command](https://github.com/Pepelux/sippts/wiki/Command-spoof)

  * _**video**_ plays an animated demo of the usual workflows: scan to exten to rcrack, dump to dcrack, leak to dcrack, and spoof to sniff.

  * _**rtpbleed**_ to exploit RTP Bleed vulnerability sending data to RTP ports. [Click here to read more about rtpbleed command](https://github.com/Pepelux/sippts/wiki/Command-rtpbleed)

  * _**rtcpbleed**_ to exploit RTP bleed vulnerability sending data to RTCP ports. [Click here to read more about rtcpbleed command](https://github.com/Pepelux/sippts/wiki/Command-rtcpbleed)

  * _**rtpbleedflood**_ to exploit RTP Bleed vulnerability flooding a RTP port with an active dialog. [Click here to read more about rtpbleedflood command](https://github.com/Pepelux/sippts/wiki/Command-rtpbleedflood)

  * _**rtpbleedinject**_ to exploit RTP Bleed vulnerability injecting RTP traffic. [Click here to read more about rtpbleedinject command](https://github.com/Pepelux/sippts/wiki/Command-rtpbleedinject)

## Known vulnerabilities ##

With `-cve`, the `scan` module compares what it fingerprints against a list of
known vulnerabilities that travels inside the package
(`src/sippts/data/cve.csv`). It holds around 1400 CVEs of 54 vendors, built
from the [NVD of NIST](https://nvd.nist.gov), and the version ranges come from
the CPEs of each CVE:

```bash
sippts scan -i 192.168.0.0/24 -fp -cve
```

Results whose version really falls inside the affected range are listed first.
The rest are shown behind them as merely possible, because in a scanner a CVE
that exists and is not reported is worse than one reported in excess. A row
with no range means every version of that device is affected.

Two limits worth knowing. The detection leans on the `User-Agent`, so a server
that hides it cannot be checked against anything. And some products are
versioned with letters (the A, B and C of Asterisk Business Edition, or
`beta_5`), which no numeric comparison can order: those are matched by text
only, and always come out as possible rather than confirmed.

To update the list:

```bash
sippts -up
```

which downloads it from github along with the rest of the modules.

### Rebuilding the list (maintainers) ###

`tools/cve_update.py` rebuilds `cve.csv` from the NVD. It is not something the
user of sippts runs: the idea is to regenerate it, look at the diff, commit it,
and let everybody else get it with `sippts -up`. That keeps the API key and the
rate limits of the NVD out of the middle of an audit.

```bash
./tools/cve_update.py --dry-run          # what would change, writing nothing
./tools/cve_update.py                    # rebuild it
./tools/cve_update.py --vendor yealink   # only one vendor
NVD_API_KEY=xxxx ./tools/cve_update.py   # ten times faster
```

Without an API key the NVD allows 5 requests every 30 seconds and a full run
takes around fifteen minutes. They are free at
[nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key).

Two lists at the top of the script control what is looked for. `VENDORS` holds
the vendors, and each one can be the whole vendor, a list of products, or
filtered by tag. `TAGS_VOIP` holds the tags (`voip`, `sip`, `ip_phone`, `ata`,
`pbx`, `ip_office`, `mivoice`...). The filter matters for vendors that also
make routers and firewalls: asking the NVD for the whole of Zyxel brings 3223
rows of WiFi and DSL kit that sippts is never going to see over SIP.

## Operating Systems ##
Sippts has been tested on:
  * Linux
  * MacOS

## Requirements ##
  * Python 3
  * The dependencies listed in requirements.txt, installed automatically by pip
  * For sniff, dump and pcapdump: tshark (part of Wireshark)
  * For extracting audio with pcapdump: sox and ffmpeg
  
## Installation ##
  Installing via git:
  ```bash
  git clone https://github.com/Pepelux/sippts.git
```
```bash
cd sippts
```
```bash
pip3 install .
```

