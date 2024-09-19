try:
    import cursor
except:
    pass

import time
from .color import Color
from .logos import Logo


class Video:
    def __init__(self):
        self.c = Color()

    def basic(self):
        try:
            cursor.hide()
        except: 
            pass

        self.scan(5060, 5061)
        self.exten(100, 999)
        self.rcrack()

        try:
            cursor.show()
        except: 
            pass
        exit()

    def digest(self):
        try:
            cursor.hide()
        except: 
            pass

        self.dump()
        self.dcrack()

        try:
            cursor.show()
        except: 
            pass
        exit()

    def leak(self):
        try:
            cursor.hide()
        except: 
            pass

        self.sdleak()
        self.dcrack(True)

        try:
            cursor.show()
        except: 
            pass
        exit()

    def spoof(self):
        try:
            cursor.hide()
        except: 
            pass

        self.arps()
        self.sniff()

        try:
            cursor.show()
        except: 
            pass
        exit()

    def scan(self, portstart, portend):
        # SIPPTS SCAN
        string = f"$ sippts scan -i 192.168.1.0/24 -p all -r {str(portstart)}-{str(portend)} -ua Yealink -th 500 -v -fp"

        line = ["-", "\\", "|", "/"]
        pos = 0

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("sipscan")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}192.168.1.0/24{self.c.WHITE}"
        )
        print(
            f"{self.c.BWHITE}[✓] Port range: {self.c.GREEN}{str(portstart)}-{str(portend)}{self.c.WHITE}"
        )
        print(
            f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}UDP, TCP, TLS{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Method to scan: {self.c.GREEN}OPTIONS{self.c.WHITE}")
        print(
            f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}Yealink{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}500{self.c.WHITE}")
        print(self.c.BYELLOW)

        for i in range(1, 254 + 1):
            for j in range(portstart, portend + 1):
                print(
                    f"[{line[pos]}] Scanning 192.168.1.{str(i)}:{str(j)}/UDP", end="\r"
                )
                pos += 1
                if pos > 3:
                    pos = 0
                time.sleep(0.005)
                print(
                    f"[{line[pos]}] Scanning 192.168.1.{str(i)}:{str(j)}/TCP", end="\r"
                )
                pos += 1
                if pos > 3:
                    pos = 0
                time.sleep(0.005)
                print(
                    f"[{line[pos]}] Scanning 192.168.1.{str(i)}:{str(j)}/TLS", end="\r"
                )
                pos += 1
                if pos > 3:
                    pos = 0
                time.sleep(0.005)

                if i == 25 and j == 5060:
                    print(
                        f"{self.c.WHITE}Response <200 Hi there> from 192.168.1.25:5060/UDP with User-Agent Private SIP Proxy{self.c.BYELLOW}"
                    )
                if i == 110 and j == 5061:
                    print(
                        f"{self.c.WHITE}Response <200 Ok> from 192.168.1.110:5061/TLS with User-Agent FPBX-2.11.0(11.17.1){self.c.BYELLOW}"
                    )
                if i == 170 and j == 5068:
                    print(
                        f"{self.c.WHITE}Response <200 Ok> from 192.168.1.170:5061/UDP with User-Agent Asterisk PBX 13.18.5{self.c.BYELLOW}"
                    )
                if i == 180 and j == 5060:
                    print(
                        f"{self.c.WHITE}Response <200 Ok> from 192.168.1.180:5060/UDP with Grandstream HT701 1.0.8.2{self.c.BYELLOW}"
                    )
                if i == 182 and j == 5066:
                    print(
                        f"{self.c.WHITE}Response <200 Ok> from 192.168.1.182:5066/UDP with Grandstream HT701 1.0.8.2{self.c.BYELLOW}"
                    )
                if i == 195 and j == 5070:
                    print(
                        f"{self.c.WHITE}Response <200 Ok> from 192.168.1.195:5070/UDP with Grandstream GXP2130 1.0.11.57{self.c.BYELLOW}"
                    )
                if i == 198 and j == 5060:
                    print(
                        f"{self.c.WHITE}Response <200 Ok> from 192.168.1.198:5060/UDP with Yealink W52P 25.81.0.60{self.c.BYELLOW}"
                    )

        print(self.c.WHITE)
        print(
            "+---------------+------+-------+--------------+-------------------------------+--------+--------------------+"
        )
        print(
            f"| {self.c.BWHITE}IP address{self.c.WHITE}    | {self.c.BWHITE}Port{self.c.WHITE} | {self.c.BWHITE}Proto{self.c.WHITE} | {self.c.BWHITE}Response{self.c.WHITE}     | {self.c.BWHITE}User-Agent{self.c.WHITE}                    | {self.c.BWHITE}Type{self.c.WHITE}   | {self.c.BWHITE}Fingerprinting{self.c.WHITE}     |"
        )
        print(
            "+---------------+------+-------+--------------+-------------------------------+--------+--------------------+"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.25{self.c.WHITE}  | {self.c.BMAGENTA}5060{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BBLUE}200 Hi there{self.c.WHITE} | {self.c.BYELLOW}Private Server   {self.c.WHITE}             | {self.c.BCYAN}Server{self.c.WHITE} | {self.c.BGREEN}Kamailio SIP Proxy{self.c.WHITE} |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.110{self.c.WHITE} | {self.c.BMAGENTA}5061{self.c.WHITE} | {self.c.BYELLOW}TLS{self.c.WHITE}   | {self.c.BBLUE}200 Ok{self.c.WHITE}       | {self.c.BYELLOW}FPBX-2.11.0(11.17.1){self.c.WHITE}          | {self.c.BCYAN}Server{self.c.WHITE} | {self.c.BGREEN}Asterisk{self.c.WHITE}           |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BBLUE}200 Ok{self.c.WHITE}       | {self.c.BYELLOW}Asterisk PBX 13.18.5{self.c.WHITE}          | {self.c.BCYAN}Server{self.c.WHITE} | {self.c.BGREEN}Asterisk{self.c.WHITE}           |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.180{self.c.WHITE} | {self.c.BMAGENTA}5060{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BBLUE}200 Ok{self.c.WHITE}       | {self.c.BYELLOW}Grandstream HT701 1.0.8.2{self.c.WHITE}     | {self.c.BCYAN}Device{self.c.WHITE} | {self.c.BGREEN}Grandstream{self.c.WHITE}        |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.182{self.c.WHITE} | {self.c.BMAGENTA}5066{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BBLUE}200 Ok{self.c.WHITE}       | {self.c.BYELLOW}Grandstream HT701 1.0.8.2{self.c.WHITE}     | {self.c.BCYAN}Device{self.c.WHITE} | {self.c.BGREEN}Grandstream{self.c.WHITE}        |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.175{self.c.WHITE} | {self.c.BMAGENTA}5070{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BBLUE}200 Ok{self.c.WHITE}       | {self.c.BYELLOW}Grandstream GXP2130 1.0.11.57{self.c.WHITE} | {self.c.BCYAN}Device{self.c.WHITE} | {self.c.BGREEN}Grandstream{self.c.WHITE}        |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.198{self.c.WHITE} | {self.c.BMAGENTA}5060{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BBLUE}200 Ok{self.c.WHITE}       | {self.c.BYELLOW}Yealink W52P 25.81.0.60{self.c.WHITE}       | {self.c.BCYAN}Device{self.c.WHITE} | {self.c.BGREEN}Yealink{self.c.WHITE}            |"
        )
        print(
            "+---------------+------+-------+--------------+-------------------------------+--------+--------------------+"
        )
        print("")
        print(f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}23 sec(s)")
        print("")
        print(
            self.c.YELLOW
            + "[!] Fingerprinting is based on `To-tag` and other header values. The result may not be correct"
        )
        print("[!] Tip: You can try -m REGISTER to verify the fingerprinting result")
        print(self.c.WHITE)

        time.sleep(3)

    def exten(self, extenstart, extenend):
        # SIPPTS EXTEN
        string = f"$ sippts exten -i 192.168.1.170 -r 5068 -e {str(extenstart)}-{str(extenend)}"

        line = ["-", "\\", "|", "/"]
        pos = 0

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("sipexten")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}192.168.1.170{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Port: {self.c.GREEN}5068{self.c.WHITE}")
        print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}UDP{self.c.WHITE}")
        print(
            f"{self.c.BWHITE}[✓] Exten range: {self.c.GREEN}{str(extenstart)}-{str(extenend)}{self.c.WHITE}"
        )
        print(
            f"{self.c.BWHITE}[✓] Method to scan: {self.c.GREEN}REGISTER{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}200{self.c.WHITE}")
        print(self.c.BYELLOW)

        for i in range(extenstart, extenend + 1):
            print(
                f"[{line[pos]}] Scanning 192.168.1.170:5068/UDP => Exten {str(i)}",
                end="\r",
            )
            pos += 1
            if pos > 3:
                pos = 0
            time.sleep(0.005)

        print(self.c.WHITE)
        print(
            "+---------------+------+-------+-----------+------------------+----------------------+"
        )
        print(
            f"| {self.c.BWHITE}IP address{self.c.WHITE}    | {self.c.BWHITE}Port{self.c.WHITE} | {self.c.BWHITE}Proto{self.c.WHITE} | {self.c.BWHITE}Extension{self.c.WHITE} | {self.c.BWHITE}Response{self.c.WHITE}         | {self.c.BWHITE}User-Agent{self.c.WHITE}           |"
        )
        print(
            "+---------------+------+-------+-----------+------------------+----------------------+"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}200{self.c.WHITE}       | {self.c.BRED}401 Unauthorized{self.c.WHITE} | {self.c.BBLUE}Asterisk PBX 13.18.5{self.c.WHITE} |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}201{self.c.WHITE}       | {self.c.BRED}401 Unauthorized{self.c.WHITE} | {self.c.BBLUE}Asterisk PBX 13.18.5{self.c.WHITE} |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}202{self.c.WHITE}       | {self.c.BRED}403 Forbidden{self.c.WHITE}    | {self.c.BBLUE}Asterisk PBX 13.18.5{self.c.WHITE} |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}203{self.c.WHITE}       | {self.c.BRED}401 Unauthorized{self.c.WHITE} | {self.c.BBLUE}Asterisk PBX 13.18.5{self.c.WHITE} |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}204{self.c.WHITE}       | {self.c.BRED}401 Unauthorized{self.c.WHITE} | {self.c.BBLUE}Asterisk PBX 13.18.5{self.c.WHITE} |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}205{self.c.WHITE}       | {self.c.BRED}401 Unauthorized{self.c.WHITE} | {self.c.BBLUE}Asterisk PBX 13.18.5{self.c.WHITE} |"
        )
        print(
            "+---------------+------+-------+-----------+------------------+----------------------+"
        )
        print("")
        print(f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}4 sec(s)")
        print(self.c.WHITE)

        time.sleep(3)

    def rcrack(self):
        # SIPPTS RCRACK
        string = f"$ sippts rcrack -i 192.168.1.170 -r 5068 -e 200,201,203-205 -w wordlists/rockyou.txt"

        words = [
            "123456",
            "12345",
            "123456789",
            "password",
            "iloveyou",
            "princess",
            "1234567",
            "rockyou",
            "12345678",
            "abc123",
            "nicole",
            "daniel",
            "babygirl",
            "1234",
            "monkey",
            "lovely",
            "jessica",
            "654321",
            "michael",
            "ashley",
            "qwerty",
            "111111",
            "iloveu",
            "000000",
            "michelle",
            "tigger",
            "sunshine",
            "chocolate",
            "password1",
            "soccer",
            "anthony",
            "friends",
            "butterfly",
            "purple",
            "angel",
            "jordan",
            "liverpool",
            "justin",
            "loveme",
            "fuckyou",
            "123123",
            "football",
            "secret",
            "andrea",
            "carlos",
            "jennifer",
            "joshua",
            "bubbles",
            "1234567890",
            "superman",
            "hannah",
            "amanda",
            "loveyou",
            "pretty",
            "basketball",
            "andrew",
            "passw0rd",
            "superSecret",
        ]
        extens = ["200", "201", "203", "204", "205"]
        line = ["-", "\\", "|", "/"]
        pos = 0

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("siprcrack")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}192.168.1.170{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Port: {self.c.GREEN}5068{self.c.WHITE}")
        print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}UDP{self.c.WHITE}")
        print(
            f"{self.c.BWHITE}[✓] Exten range: {self.c.GREEN}200,201,203-205{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}5{self.c.WHITE}")
        print(
            f"{self.c.BWHITE}[✓] Wordlist: {self.c.GREEN}wordlists/rockyou.txt{self.c.WHITE}"
        )
        print(self.c.BYELLOW)

        for e in extens:
            for w in words:
                if (
                    (e == "200" and w == "1234")
                    or (e == "201" and w == "iloveyou")
                    or (e == "203" and w == "monkey")
                    or (e == "204" and w == "passw0rd")
                    or (e == "205" and w == "superSecret")
                ):
                    print(
                        f"{self.c.WHITE}Password for user {self.c.BBLUE}{e}{self.c.WHITE} found: {self.c.BRED}{w}{self.c.WHITE}                                                                "
                    )
                else:
                    print(
                        f"{self.c.BYELLOW}[{line[pos]}] {self.c.BWHITE}Scanning {self.c.BYELLOW}192.168.1.170:5068/UDP{self.c.BWHITE} => Exten/Pass: {self.c.BGREEN}{e}/{w} {self.c.BBLUE}- 403 Forbidden         ",
                        end="\r",
                    )

                pos += 1
                if pos > 3:
                    pos = 0
                time.sleep(0.05)

        print(self.c.WHITE)
        print("+---------------+------+-------+------+--------------+")
        print(
            f"| {self.c.BWHITE}IP address{self.c.WHITE}    | {self.c.BWHITE}Port{self.c.WHITE} | {self.c.BWHITE}Proto{self.c.WHITE} | {self.c.BWHITE}User{self.c.WHITE} | {self.c.BWHITE}Password{self.c.WHITE}     |"
        )
        print("+---------------+------+-------+------+--------------+")
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}200{self.c.WHITE}  | {self.c.BRED}1234{self.c.WHITE}         |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}201{self.c.WHITE}  | {self.c.BRED}iloveyou{self.c.WHITE}     |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}203{self.c.WHITE}  | {self.c.BRED}monkey{self.c.WHITE}       |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}204{self.c.WHITE}  | {self.c.BRED}passw0rd{self.c.WHITE}     |"
        )
        print(
            f"| {self.c.BGREEN}192.168.1.170{self.c.WHITE} | {self.c.BMAGENTA}5068{self.c.WHITE} | {self.c.BYELLOW}UDP{self.c.WHITE}   | {self.c.BCYAN}205{self.c.WHITE}  | {self.c.BRED}superSecret{self.c.WHITE}  |"
        )
        print("+---------------+------+-------+------+--------------+")
        print("")
        print(f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}2 min(s) 24 sec(s)")
        print(self.c.WHITE)

        time.sleep(3)

    def dump(self):
        # SIPPTS DUMP
        string = f"$ sippts dump -f capture.pcap -o auth_users.txt"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("sipdump")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Input file: {self.c.GREEN}capture.pcap{self.c.WHITE}"
        )
        print(
            f"{self.c.BWHITE}[✓] Output file: {self.c.GREEN}auth_users.txt{self.c.WHITE}"
        )
        print(self.c.BYELLOW)

        time.sleep(2)

        print(self.c.WHITE)
        print(
            f"[{self.c.BYELLOW}192.168.100.101{self.c.BWHITE} => {self.c.BYELLOW}192.168.100.1{self.c.BWHITE}] User: {self.c.BGREEN}103{self.c.BWHITE} - URI: {self.c.BCYAN}sip:192.168.100.1:15080{self.c.BWHITE} - Hash: {self.c.BRED}8019826a79ea06599d195958112da835{self.c.BWHITE}"
        )
        print(
            f"[{self.c.BYELLOW}192.168.100.102{self.c.BWHITE} => {self.c.BYELLOW}192.168.100.1{self.c.BWHITE}] User: {self.c.BGREEN}105{self.c.BWHITE} - URI: {self.c.BCYAN}sip:192.168.100.1:15080{self.c.BWHITE} - Hash: {self.c.BRED}51ff2a74732e7c745f7882b1b281f2fa{self.c.BWHITE}"
        )
        print(self.c.WHITE)

        time.sleep(2)

        string = f"$ cat s.txt"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        print(
            '192.168.100.101"192.168.100.1"103"asterisk"REGISTER"sip:192.168.100.1:15080"2c7dd6c8""""MD5"8019826a79ea06599d195958112da835'
        )
        print(
            '192.168.100.102"192.168.100.1"105"asterisk"REGISTER"sip:192.168.100.1:15080"345e7ab8""""MD5"51ff2a74732e7c745f7882b1b281f2fa'
        )
        print(self.c.WHITE)

        time.sleep(3)

    def dcrack(self, leak=False):
        # SIPPTS DCRACK
        string = f"$ sippts dcrack -f auth_users.txt -w wordlists/rockyou.txt"

        words = [
            "123456",
            "12345",
            "123456789",
            "password",
            "iloveyou",
            "princess",
            "1234567",
            "rockyou",
            "12345678",
            "abc123",
            "nicole",
            "daniel",
            "babygirl",
            "1234",
            "monkey",
            "lovely",
            "jessica",
            "654321",
            "michael",
            "ashley",
            "qwerty",
            "111111",
            "iloveu",
            "000000",
            "michelle",
            "tigger",
            "sunshine",
            "chocolate",
            "password1",
            "soccer",
            "anthony",
            "friends",
            "butterfly",
            "purple",
            "angel",
            "jordan",
            "liverpool",
            "justin",
            "loveme",
            "fuckyou",
            "123123",
            "football",
            "secret",
            "andrea",
            "carlos",
            "jennifer",
            "joshua",
            "bubbles",
            "1234567890",
            "superman",
            "hannah",
            "amanda",
            "loveyou",
            "pretty",
            "basketball",
            "andrew",
            "passw0rd",
            "superSecret",
        ]
        if leak == False:
            extens = ["103", "105"]
        else:
            extens = ["103"]
        line = ["-", "\\", "|", "/"]
        pos = 0

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("sipdigestcrack")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Input file: {self.c.GREEN}auth_users.txt{self.c.WHITE}"
        )
        print(
            f"{self.c.BWHITE}[✓] Wordlist: {self.c.GREEN}wordlists/rockyou.txt{self.c.WHITE}"
        )
        print(self.c.BYELLOW)

        for e in extens:
            found = 0
            if e == "103":
                print(
                    f"{self.c.BYELLOW}[+] Trying to crack hash 8019826a79ea06599d195958112da835 of the user 103 ..."
                )
            else:
                print(
                    f"{self.c.BYELLOW}[+] Trying to crack hash 51ff2a74732e7c745f7882b1b281f2fa of the user 105 ..."
                )

            for w in words:
                if found == 0:
                    if (e == "103" and w == "123456") or (e == "105" and w == "secret"):
                        print(
                            f"{self.c.WHITE}Password for user {self.c.BBLUE}{e}{self.c.WHITE} found: {self.c.BRED}{w}{self.c.WHITE}                                                                "
                        )
                        found = 1
                    else:
                        print(
                            f"{self.c.BYELLOW}[{line[pos]}] {self.c.BWHITE}Trying pass {self.c.BYELLOW}{w}{self.c.WHITE}         ",
                            end="\r",
                        )

                    pos += 1
                    if pos > 3:
                        pos = 0
                    time.sleep(0.05)

        print(self.c.WHITE)
        print("+-----------------+----------------+----------+----------+")
        print(
            f"| {self.c.BWHITE}Source IP{self.c.WHITE}       | {self.c.BWHITE}Destination IP{self.c.WHITE} | {self.c.BWHITE}Username{self.c.WHITE} | {self.c.BWHITE}Password{self.c.WHITE} |"
        )
        print("+-----------------+----------------+----------+----------+")
        print(
            f"| {self.c.BGREEN}192.168.100.101{self.c.WHITE} | {self.c.BMAGENTA}192.168.100.1{self.c.WHITE}  | {self.c.BYELLOW}103{self.c.WHITE}      | {self.c.BRED}123456{self.c.WHITE}   |"
        )
        if leak == False:
            print(
                f"| {self.c.BGREEN}192.168.100.102{self.c.WHITE} | {self.c.BMAGENTA}192.168.100.1{self.c.WHITE}  | {self.c.BYELLOW}105{self.c.WHITE}      | {self.c.BRED}secret{self.c.WHITE}   |"
            )
        print("+-----------------+----------------+----------+----------+")
        print(self.c.WHITE)

        time.sleep(3)

    def sdleak(self):
        # SIPPTS LEAK
        string = f"$ sippts leak -i 192.168.100.101 -o auth_users.txt"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("sipdigestleak")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Target: {self.c.GREEN}192.168.100.101{self.c.WHITE}:{self.c.GREEN}5060{self.c.WHITE}/{self.c.GREEN}UDP"
        )
        print(
            f"{self.c.BWHITE}[✓] Output file: {self.c.GREEN}auth_users.txt{self.c.WHITE}"
        )
        print(self.c.BYELLOW)

        time.sleep(2)

        print(self.c.WHITE)
        print(f"{self.c.YELLOW}[=>] Request INVITE")
        time.sleep(0.5)
        print(f"{self.c.CYAN}[<=] Response 100 Trying")
        time.sleep(0.5)
        print(f"{self.c.CYAN}[<=] Response 180 Ringing")
        time.sleep(0.5)
        print(f"{self.c.CYAN}[<=] Response 200 Ok")
        time.sleep(0.5)
        print(f"{self.c.YELLOW}[=>] Request ACK")
        print(f"{self.c.WHITE}      ... waiting for BYE ...")
        time.sleep(2)
        print(f"{self.c.CYAN}[<=] Received BYE")
        time.sleep(0.5)
        print(f"{self.c.YELLOW}[=>] Request 407 Proxy Authentication Required")
        time.sleep(0.5)
        print(f"{self.c.CYAN}[<=] Received BYE")
        time.sleep(0.5)
        print(f"{self.c.YELLOW}[=>] Request 200 Ok")
        time.sleep(0.5)
        print(
            f'{self.c.GREEN}Auth=Digest username="103", realm="asterisk", nonce="2c7dd6c8", uri="sip:192.168.100.1:15080", response="8019826a79ea06599d195958112da835", algorithm=MD5'
        )
        print(self.c.WHITE)

        time.sleep(2)

        string = f"$ cat s.txt"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        print(
            '192.168.100.101"192.168.100.1"103"asterisk"REGISTER"sip:192.168.100.1:15080"2c7dd6c8""""MD5"8019826a79ea06599d195958112da835'
        )
        print(self.c.WHITE)

        time.sleep(3)

    def arps(self):
        # SIPPTS SPOOF
        print("MacOS systems ...")
        string = "$ sudo sysctl -w net.inet.ip.forwarding=1"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print("\n")

        print("Linux systems ...")
        string = "$ sysctl net.ipv4.ip_forward=1"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print("\n")

        string = "$ sudo sippts spoof -i 192.168.100.101,192.168.100.102,192.168.100.103 -gw 192.168.100.1 -v"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("arpspoof")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Operating System: {self.c.GREEN}Darwin{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Current User: {self.c.GREEN}pepelux{self.c.WHITE}")
        print(
            f"{self.c.BWHITE}[✓] Local IP address: {self.c.GREEN}192.168.100.115{self.c.WHITE}"
        )
        print(
            f"{self.c.BWHITE}[✓] Target IP/range: {self.c.GREEN}192.168.100.101,192.168.100.102,192.168.100.103{self.c.WHITE}"
        )
        print(f"{self.c.BWHITE}[✓] Gateway: {self.c.GREEN}192.168.100.1{self.c.WHITE}")
        print(self.c.BYELLOW)
        print(f"{self.c.BWHITE}[!] Enabling IP Routing...{self.c.WHITE}")
        print(self.c.BYELLOW)

        time.sleep(2)

        print(
            f"{self.c.YELLOW}[+] Start ARP spoof between 192.168.100.101 (c0:71:ad:88:76:a8) and 192.168.100.1 (34:60:12:8c:aa:8c)"
        )
        time.sleep(0.5)
        print(
            f"{self.c.YELLOW}[+] Start ARP spoof between 192.168.100.102 (00:0b:62:53:69:f1) and 192.168.100.1 (34:60:12:8c:aa:8c)"
        )
        time.sleep(0.5)
        print(
            f"{self.c.YELLOW}[+] Start ARP spoof between 192.168.100.103 (00:0b:09:53:62:e3) and 192.168.100.1 (34:60:12:8c:aa:8c)"
        )
        time.sleep(0.5)
        print(self.c.WHITE)

        time.sleep(2)

        print("---------- Open another terminal ----------\n")

        time.sleep(3)

    def sniff(self):
        # SIPPTS SPOOF
        string = "$ sippts sniff -d eth0 -p all"

        for i in range(1, len(string) + 1):
            print(string[0:i], end="\r")
            time.sleep(0.05)

        print()

        logo = Logo("sipsniff")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Listening on: {self.c.GREEN}eth0{self.c.WHITE}")
        print(
            f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}UDP, TCP, TLS{self.c.WHITE}"
        )
        print(self.c.BYELLOW)

        time.sleep(2)

        print(
            f"{self.c.WHITE}Found TLS connection 192.168.100.254:5061 => 192.168.100.102:45261"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.YELLOW}Found TLS connection 192.168.100.254:5061 => 192.168.100.102:45261"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.YELLOW}Found TLS connection 192.168.100.254:5061 => 192.168.100.102:45261"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[REGISTER] 192.168.100.103:17847 => 192.168.100.254:5060 - Grandstream GXP2140 1.0.11.64"
        )
        time.sleep(0.5)
        print(
            f"{self.c.CYAN}Found Domain sip.domain.com for user 200 connecting to 192.168.100.254:5060"
        )
        time.sleep(0.5)
        print(
            f'{self.c.GREEN}Auth=Digest username="200", realm="asterisk", nonce="ZnVpBmZ1Z9pQe+46LdSRwOfcIw1og0Vq", uri="sip:sip.domain.com", response="0a6ba94c31555646b78b8e595d640dec", algorithm=MD5, cnonce="07055581", qop=auth, nc=00000006'
        )
        print(f"{self.c.WHITE}")
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[SUBSCRIBE] 192.168.100.101:26085 => 192.168.100.254:5060 - Grandstream GXP2130 1.0.11.16"
        )
        time.sleep(0.5)
        print(
            f"{self.c.WHITE}[NOTIFY] 192.168.100.254:5060 => 192.168.100.101:26085 - Asterisk PBX 13.18.5"
        )
        time.sleep(0.5)
        print(
            f"{self.c.YELLOW}Found TLS connection 192.168.100.254:5061 => 192.168.100.102:45261"
        )

        time.sleep(3)
