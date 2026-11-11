#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import random
import signal
import socket
import sys
import ssl
import re
import time

try:
    import cursor
except:
    pass

from .lib.functions import (
    open_log,
    create_message,
    parse_message,
    close_sockets,
    host_sort_key,
    get_machine_default_ip,
    expand_targets,
    bind_local_port,
    ping,
    fingerprinting,
    format_time,
    load_cve,
    check_model,
    write_targets,
    write_results,
    result_rows,
    RESULT_FIELDS,
    cvss_text,
    cvss_severity,
    cvss_score,
    cvss_version,
    get_free_port,
    generate_random_string,
)
from .lib.wsclient import ws_connect, ws_send_recv, ws_error_text, is_timeout
from .lib.color import Color
from .lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED
from concurrent.futures import wait as futures_wait
import resource as res

class SipScan:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.path = ""
        self.httpfound = False
        self.method = "OPTIONS"
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.user_agent = "pplsip"
        self.threads = 200
        self.verbose = 0
        self.ping = 0
        self.file = ""
        self.nocolor = ""
        self.ofile = ""
        self.oifile = ""
        self.otfile = ""
        self.ojson = ""
        self.ocsv = ""
        self.fp = 0
        self.random = 0
        self.ppi = ""
        self.pai = ""
        self.localip = ""
        self.getcve = 0
        self.timeout = 5

        self.forcedomain = False

        self.found = []
        self.ipsfound = []
        self.line = ["-", "\\", "|", "/"]
        self.pos = 0
        self.quit = False
        self.totaltime = 0
        self.fail = 0
        self.errors = 0
        self.closed = 0
        self.tlsinfo = 0
        self.tls = []
        self.tlsfindings = []
        self.tlsseen = set()
        self.tlsversions = 0
        self.header = ""
        self.tlsver = []
        self.cvelist = []
        self.cve = []

        self.c = Color()
        

    def stop(self):
        try:
            cursor.show()
        except:
            pass
        print(self.c.WHITE)
        self.quit = True


    def set_ulimit(self, threads):
        # Get current 'ulimit -n' value
        soft,hard = res.getrlimit(res.RLIMIT_NOFILE)
        
        # If ulimit < threads, set new value
        if soft < int(threads):
            soft = threads + 100

        if hard < soft:
            hard = soft

        try:
            res.setrlimit(res.RLIMIT_NOFILE,(soft,hard))
        except (ValueError,res.error):
            try:
                hard = soft
                # Trouble with max limit, retrying with soft,hard
                res.setrlimit(res.RLIMIT_NOFILE,(soft,hard))
            except Exception:
                # Failed to set ulimit, setting new threads value
                soft,hard = res.getrlimit(res.RLIMIT_NOFILE)
                self.threads = soft


    def start(self):
        # reset the stop flag: after a Ctrl+C the object kept it set, so from
        # sippts-gui (where the module instance is reused) every later run
        # did nothing at all
        self.quit = False

        self.threads = int(self.threads)
        self.set_ulimit(self.threads)
    
        supported_protos = ["UDP", "TCP", "TLS", "WS", "WSS"]
        supported_methods = ["OPTIONS", "REGISTER", "INVITE"]

        if self.nocolor == 1:
            self.c.ansy()

        self.method = self.method.upper()
        self.proto = self.proto.upper()
        if self.proto == "UDP|TCP|TLS":
            self.proto = "ALL"

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.ping = int(self.ping)
        except:
            self.ping = 0

        try:
            self.fp = int(self.fp)
        except:
            self.fp = 0

        try:
            self.random = int(self.random)
        except:
            self.random = 0

        try:
            self.getcve = int(self.getcve)
        except:
            self.getcve = 0

        try:
            self.timeout = float(self.timeout)
        except (TypeError, ValueError):
            self.timeout = 5

        # check method
        if self.method not in supported_methods:
            print(f"{self.c.BRED}Method {self.method} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # my IP address
        local_ip = self.localip
        if self.localip == "":
            try:
                local_ip = get_machine_default_ip()
                self.localip = local_ip
            except:
                print(f"{self.c.BRED}Error getting local IP")
                print(
                    f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.c.BWHITE} param"
                )
                print(self.c.WHITE)
                sys.exit()

        if self.rport.upper() == "ALL":
            self.rport = "1-65535"

        logo = Logo("sipscan", self.nocolor)
        logo.print()

        # create a list of protocols. -p takes one transport, ALL, or a comma
        # separated list (-p udp,tls,wss): scanning two transports is a normal
        # thing to ask for and there is no reason to force two runs
        self.proto = str(self.proto).upper().strip()
        protos = []
        if self.proto == "ALL":
            protos = list(supported_protos)
        else:
            for p in self.proto.split(","):
                p = p.strip()
                if p == "":
                    continue
                if p not in supported_protos:
                    print(
                        f"{self.c.RED}[!] Invalid protocol: {self.c.BRED}{p}{self.c.RED} (choose from {', '.join(supported_protos)} or ALL, comma separated){self.c.WHITE}"
                    )
                    return
                if p not in protos:
                    protos.append(p)

        if len(protos) == 0:
            print(f"{self.c.RED}[!] No protocol to scan{self.c.WHITE}")
            return

        # keep a stable transport order whatever the order on the command line
        protos.sort(key=lambda x: supported_protos.index(x))

        # create a list of ports
        ports = []
        for p in self.rport.split(","):
            p = p.strip()
            m = re.fullmatch(r"([0-9]+)-([0-9]+)", p)
            if m:
                pini = max(int(m.group(1)), 1)
                pend = min(int(m.group(2)), 65535)

                for x in range(pini, pend + 1):
                    ports.append(x)
            else:
                if not p.isdigit() or int(p) < 1 or int(p) > 65535:
                    print(f"{self.c.BRED}Invalid port {p} (valid range is 1-65535)")
                    print(self.c.WHITE)
                    sys.exit()

                ports.append(int(p))

        if ports == []:
            print(f"{self.c.BRED}No valid ports to scan in {self.rport}")
            print(self.c.WHITE)
            sys.exit()

        # load cve file
        self.cvelist = load_cve()

        # create a list of IP addresses
        if self.file != "":
            try:
                f = open(self.file)
            except OSError:
                print(f"{self.c.RED}Error reading file {self.file}")
                print(self.c.WHITE)
                sys.exit()

            with f:
                for line in f:
                    if self.quit == True:
                        break

                    line = line.strip()

                    if line == "":
                        continue

                    try:
                        (ips, names) = expand_targets(line)
                    except ValueError as error:
                        print(f"{self.c.RED}{error}")
                        print(self.c.WHITE)
                        continue

                    self.prepare_scan(
                        self.select_hosts(ips), ports, protos, line
                    )
        else:
            try:
                (ips, names) = expand_targets(self.ip)
            except ValueError as error:
                print(f"{self.c.RED}{error}")
                print(self.c.WHITE)
                sys.exit()

            if ips == []:
                print(f"{self.c.RED}No target to scan in {self.ip}")
                print(self.c.WHITE)
                sys.exit()

            # a single host given by name is used as SIP domain
            if self.domain == "" and len(names) == 1 and len(ips) == 1:
                self.domain = names[0]
                self.forcedomain = True

            self.prepare_scan(self.select_hosts(ips), ports, protos, self.ip)

    def select_hosts(self, ips):
        """
        Drop the local address from the list of targets and, with -ping, the
        hosts that do not answer to a ping.
        """
        selected = []

        for ip in ips:
            if self.quit == True:
                break

            if ip == self.localip:
                continue

            if self.ping == 0:
                selected.append(ip)
            else:
                print(
                    f"{self.c.YELLOW}[+] Ping {ip} ...{self.c.WHITE}",
                    end="\r",
                )

                if ping(ip, "0.1") == True:
                    print(f"{self.c.GREEN}\n   [-] ... Pong {ip}{self.c.WHITE}")
                    selected.append(ip)

        return selected

    def prepare_scan(self, ips, ports, protos, iplist):
        # threads to use
        self.threads = int(self.threads)
        nthreads = self.threads
        total = len(ips) * len(ports) * len(protos)
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{str(iplist)}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(f"{self.c.BWHITE}[✓] Port range: {self.c.GREEN}{self.rport}")
        # the normalized list, not what was typed: -p wss,udp,udp,tls has to
        # read back as the three transports that will actually be scanned
        if len(protos) > 1:
            print(f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}{', '.join(protos)}")
        else:
            print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}{protos[0]}")
        if ("WS" in protos or "WSS" in protos) and self.path != "":
            print(f"{self.c.BWHITE}[✓] WS path: {self.c.GREEN}{self.path}")

        print(f"{self.c.BWHITE}[✓] Method to scan: {self.c.GREEN}{self.method}")

        if (
            (self.domain != ""
            and self.domain != str(self.ip)
            and self.domain != self.host) or self.forcedomain
        ):
            print(f"{self.c.BWHITE}[✓] Customized Domain: {self.c.GREEN}{self.domain}")
        if self.contact_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized Contact Domain: {self.c.GREEN}{self.contact_domain}"
            )
        if self.from_name != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From Name: {self.c.GREEN}{self.from_name}"
            )
        if self.from_user != "100":
            print(
                f"{self.c.BWHITE}[✓] Customized From User: {self.c.GREEN}{self.from_user}"
            )
        if self.from_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From Domain: {self.c.GREEN}{self.from_domain}"
            )
        if self.to_name != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Name: {self.c.GREEN}{self.to_name}"
            )
        if self.to_user != "100":
            print(f"{self.c.BWHITE}[✓] Customized To User:{self.c.GREEN}{self.to_user}")
        if self.to_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Domain: {self.c.GREEN}{self.to_domain}"
            )
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}{str(nthreads)}")
        # a full `-r all -p all` is 327675 probes: saying so up front
        # saves wondering whether the scan is stuck
        if total > 10000:
            print(f"{self.c.BWHITE}[✓] Probes to send: {self.c.GREEN}{str(total)}")
        if self.file != "":
            print(
                f"{self.c.BWHITE}[✓] Loading data from file: {self.c.CYAN}{self.file}"
            )
        if self.ofile != "":
            print(
                f"{self.c.BWHITE}[✓] Saving logs info file: {self.c.CYAN}{self.ofile}"
            )
        if self.oifile != "":
            print(
                f"{self.c.BWHITE}[✓] Saving IPs info file: {self.c.CYAN}{self.oifile}"
            )
        if self.random == 1:
            print(f"{self.c.BWHITE}[✓] Random hosts: {self.c.GREEN}True")
        print(self.c.WHITE)

        values = product(ips, ports, protos)

        # -random cannot work on a generator, so only in that case the whole
        # product is materialized (a tuple per probe, ~40MB for 65535 ports x 5
        # transports) and shuffled once. It used to be shuffled per 100k batch,
        # which was not a global shuffle anyway
        if self.random == 1:
            values = list(values)
            random.shuffle(values)

        # how many futures may be alive at the same time. Submitting every
        # probe up front cost ~360MB of RSS for `-r all -p all` (327675 probes)
        # before the first packet left the box, and on a machine under memory
        # pressure the process was killed outright. Keeping a small window
        # ahead of the pool is just as fast -- the threads never starve -- and
        # it also makes Ctrl+C immediate, because there is almost nothing left
        # to cancel
        window = max(nthreads * 4, 16)
        tareas = set()

        start = time.time()

        executor = ThreadPoolExecutor(max_workers=nthreads)

        try:
            for val in values:
                if self.quit == True:
                    break

                val_ipaddr = val[0]
                val_port = int(val[1])
                val_proto = val[2]

                # several transports with the default port: each one has its
                # own well-known port, SIP over WebSocket does not live on
                # 5060 (Asterisk: 8088/8089). Only when -r was not given, an
                # explicit port is always honoured
                if len(protos) > 1 and self.rport == "5060":
                    if val_proto == "TLS":
                        val_port = 5061
                    if val_proto == "WS":
                        val_port = 8088
                    if val_proto == "WSS":
                        val_port = 8089

                tareas.add(
                    executor.submit(
                        self.scan_host,
                        val_ipaddr,
                        val_port,
                        val_proto,
                    )
                )

                # waiting in short slices instead of a single blocking join:
                # the main thread has to come back to the interpreter often
                # enough for a Ctrl+C to be seen at all. Blocked inside
                # executor.shutdown(wait=True) the signal was only processed
                # when every thread had finished, so the tool looked frozen
                # and the second Ctrl+C came out as a traceback
                while len(tareas) >= window and self.quit == False:
                    done, tareas = futures_wait(
                        tareas, timeout=0.5, return_when=FIRST_COMPLETED
                    )
                    tareas = set(tareas)

            while len(tareas) > 0 and self.quit == False:
                done, tareas = futures_wait(
                    tareas, timeout=0.5, return_when=FIRST_COMPLETED
                )
                tareas = set(tareas)

            try:
                cursor.show()
            except:
                pass
        except KeyboardInterrupt:
            print(f"{self.c.RED}\nYou pressed Ctrl+C!")
            try:
                cursor.show()
            except:
                pass
            print(self.c.WHITE)
            self.quit = True

            # ignore any further Ctrl+C or kill: from here on the only
            # thing left is printing what was found, and a second one used to
            # come out as a traceback from the thread shutdown
            for signame in ("SIGINT", "SIGTERM", "SIGHUP"):
                try:
                    signal.signal(getattr(signal, signame), signal.SIG_IGN)
                except Exception:
                    pass

        # drop what has not started yet, instead of waiting for the whole
        # queue to go through. The threads already inside a socket are left to
        # their timeout, nothing is joined
        for tarea in tareas:
            tarea.cancel()

        executor.shutdown(wait=False, cancel_futures=True)

        end = time.time()
        self.totaltime = int(end - start)

        self.found.sort(key=host_sort_key)
        self.ipsfound.sort(key=host_sort_key)
        self.print()
        if len(self.cve) > 0:
            self.print_cve()

        if len(self.tls) > 0:
            self.tls.sort(key=host_sort_key)
            # the worst first: alphabetical order put CERT_DEFAULT_VENDOR
            # above CERT_EXPIRED for no reason
            orden = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
            self.tlsfindings.sort(
                key=lambda x: (
                    host_sort_key(x),
                    orden.get(x.split("###")[2], 9) if len(x.split("###")) > 2 else 9,
                    x,
                )
            )
            self.print_tls()

        try:
            cursor.show()
        except:
            pass

    def scan_host(self, ipaddr, port, proto):
        if self.quit == False:
            headers = None
            sock_ssl = None

            try:
                cursor.hide()
            except:
                pass
            print(
                f"{self.c.BYELLOW}[{self.line[self.pos]}] Scanning {ipaddr}:{str(port)}/{proto}{' '.ljust(100)}",
                end="\r",
            )
            self.pos += 1
            if self.pos > 3:
                self.pos = 0

            if proto in ("WS", "WSS"):
                # SIP over WebSocket (RFC 7118) does not go through a raw
                # socket: the handshake and the framing are done by the shared
                # client, and the answer ends in the same table
                return self.scan_host_ws(ipaddr, port, proto)

            try:
                if proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                self.fail += 1

                if self.fail > 50:
                    print(
                        f"{self.c.RED}Too many socket connection errors. Consider reducing the number of threads"
                    )
                    self.quit = True
                    return
                print(f"{self.c.RED}Failed to create socket")
                return

            bind = "0.0.0.0"
            lport = bind_local_port(sock, bind)

            if lport == 0:
                sock.close()
                self.fail += 1

                if self.fail > 50:
                    print(
                        f"{self.c.RED}Too many socket bind errors. Consider reducing the number of threads"
                    )
                    self.quit = True
                    return

                if self.verbose == 2:
                    print(f"{self.c.RED}\nFailed to bind a local port{self.c.WHITE}")
                return

            if self.proxy == "":
                host = (str(ipaddr), port)
            else:
                if self.proxy.find(":") > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(":")
                else:
                    proxy_ip = self.proxy
                    proxy_port = "5060"

                host = (str(proxy_ip), int(proxy_port))

            msg = self.build_message(ipaddr, proto, lport)

            try:
                sock.settimeout(self.timeout)

                if proto == "TCP":
                    sock.connect(host)

                if proto == "TLS":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.load_default_certs()

                    # the SNI: the address was always sent, so a SIP-TLS with
                    # virtual hosts handed back its default certificate
                    sni = self.domain if self.domain not in ("", None) else str(host[0])

                    sock_ssl = context.wrap_socket(sock, server_hostname=str(sni))
                    sock_ssl.connect(host)

                    if self.tlsinfo == 1:
                        # read before sending anything: the handshake has
                        # already happened, so this costs no extra connection,
                        # and a host whose TLS answers but whose SIP does not
                        # still gets reported
                        try:
                            self.inspect_tls(sock_ssl, ipaddr, port, sni)
                        except Exception:
                            self.errors += 1

                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), (host))

                if self.verbose == 2:
                    print(
                        f"{self.c.BWHITE}[+] Sending to {ipaddr}:{str(port)}/{proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}")

                rescode = "100"
                # a peer that keeps answering 1xx used to keep this loop going forever
                tries = 0

                while rescode[:1] == "1" and tries < 10:
                    tries += 1

                    # receive temporary code
                    if proto == "TLS":
                        resp = sock_ssl.recv(4096)
                        (ip, rport) = host
                    else:
                        (resp, addr) = sock.recvfrom(4096)
                        (ip, rport) = host

                    headers = parse_message(resp.decode())

                    if headers and headers["response_code"] != "":
                        response = "%s %s" % (
                            headers["response_code"],
                            headers["response_text"],
                        )
                        rescode = headers["response_code"]

                    if self.verbose == 2:
                        print(
                            f"{self.c.BWHITE}[-] Receiving from {ipaddr}:{rport}/{proto} ..."
                        )
                        print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")

                    if headers["response_code"] == "":
                        rescode = ""

                        # neither a plain HTTP answer nor a SIP request is a
                        # broken SIP answer: the first is a web server (or a
                        # SIP-over-WebSocket port asked the wrong way), the
                        # second an echo or a host that answers with a
                        # request. process_answer() puts both in the table
                        texto = resp.decode(errors="replace")
                        if not texto.startswith("HTTP/") and not self.is_sip_request(texto):
                            print(
                                f"{self.c.RED}\nEmpty response code: {self.c.YELLOW}{ipaddr}:{str(port)}/{proto}: {self.c.CYAN}{resp}\n{self.c.WHITE}"
                            )

                headers = self.process_answer(resp.decode(), ip, rport, proto, msg)
            except socket.timeout:
                pass
            except Exception as error:
                # counted, so a scan that swallows errors says so at the end
                if self.is_closed_port(error):
                    self.closed += 1
                else:
                    self.errors += 1

                if self.verbose == 2:
                    print(f"{self.c.RED}\n{error}{self.c.WHITE}")
                pass
            finally:
                close_sockets(sock, sock_ssl)

            return headers




    def scan_host_ws(self, ipaddr, port, proto):
        """Scan one SIP-over-WebSocket port."""
        headers = None
        conn = None

        lport = get_free_port()
        # RFC 7118: a WebSocket client has no address of its own, Via and
        # Contact carry a random .invalid host
        contact = "%s.invalid" % generate_random_string(12, 12, "hex")
        msg = self.build_message(ipaddr, proto, lport, contact)

        sni = self.domain if self.domain not in ("", None) else str(ipaddr)

        try:
            conn, url = ws_connect(
                proto,
                ipaddr,
                port,
                self.path,
                timeout=self.timeout,
                sni=sni,
            )

            if self.verbose == 2:
                print(f"{self.c.BWHITE}[+] Sending to {url} ...")
                print(f"{self.c.YELLOW}{msg}")

            if proto == "WSS" and self.tlsinfo == 1:
                try:
                    self.inspect_tls(conn.sock, ipaddr, port, sni)
                except Exception:
                    self.errors += 1

            answer = ws_send_recv(conn, msg, timeout=self.timeout)

            if answer == "":
                if self.verbose == 2:
                    print(
                        f"{self.c.RED}\nNo SIP answer from {ipaddr}:{str(port)}/{proto}{self.c.WHITE}"
                    )

                return headers

            if self.verbose == 2:
                print(f"{self.c.BWHITE}[-] Receiving from {ipaddr}:{str(port)}/{proto} ...")
                print(f"{self.c.GREEN}{answer}{self.c.WHITE}")

            headers = self.process_answer(answer, str(ipaddr), int(port), proto, msg)
        except Exception as error:
            # a timeout is what a closed port looks like over WebSocket, and
            # UDP/TCP/TLS already pass over theirs without a word: counting it
            # as an error here was what filled the summary with thousands of
            # them on a -r all scan
            if is_timeout(error):
                self.closed += 1
            elif self.is_closed_port(error):
                self.closed += 1
            else:
                self.errors += 1

            if self.verbose == 2:
                print(f"{self.c.RED}\n{ws_error_text(error)}{self.c.WHITE}")
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

        return headers

    def build_message(self, ipaddr, proto, lport, contact_default="10.0.0.1"):
        """The request this scan sends, built once for every transport."""
        domain = self.domain
        if domain == "":
            domain = ipaddr

        contact_domain = self.contact_domain
        if contact_domain == "":
            contact_domain = contact_default

        fdomain = self.from_domain
        tdomain = self.to_domain

        if not self.from_domain or self.from_domain == "":
            fdomain = domain
        if not self.to_domain or self.to_domain == "":
            tdomain = domain

        if self.method == "REGISTER":
            if self.to_user == "100" and self.from_user != "100":
                self.to_user = self.from_user
            if self.to_user != "100" and self.from_user == "100":
                self.from_user = self.to_user

        if self.proxy != "":
            self.route = "<sip:%s;lr>" % self.proxy

        msg = create_message(
            self.method,
            "",
            contact_domain,
            self.from_user,
            self.from_name,
            fdomain,
            self.to_user,
            self.to_name,
            tdomain,
            proto,
            domain,
            self.user_agent,
            lport,
            "",
            "",
            "",
            "1",
            "",
            "",
            1,
            "",
            0,
            "",
            self.route,
            self.ppi,
            self.pai,
            self.header,
            1,
        )

        return msg


    def process_http_answer(self, resptext, ip, rport, proto):
        """A port that answers HTTP instead of SIP.

        Asterisk serves its WebSocket on the same port as its web server, so
        asking it with -p tcp/tls gets a 404 back. That used to be printed as
        an "Empty response code" dump and lost, when it is in fact the most
        useful thing the port said: there is something there, try -p ws|wss.
        """
        lines = resptext.replace("\r\n", "\n").split("\n")
        status = lines[0].strip()

        server = ""
        for linea in lines[1:]:
            if linea.strip() == "":
                break

            if linea.lower().startswith("server:"):
                server = linea.split(":", 1)[1].strip()
                break

        # the status line without the HTTP version reads like the SIP ones
        response = status
        m = re.search(r"^HTTP/[\d.]+\s+(.+)$", status)
        if m:
            response = "HTTP %s" % m.group(1)

        self.httpfound = True

        line = "%s###%d###%s###%s###%s###%s###%s" % (
            ip,
            rport,
            proto,
            response,
            server,
            "Web server",
            "",
        )

        if line not in self.found:
            self.found.append(line)

        if self.oifile != "" and ip not in self.ipsfound:
            self.ipsfound.append(ip)

        if self.verbose == 1:
            print(
                f"{self.c.WHITE}Response <{response}> from {ip}:{str(rport)}/{proto}, not SIP but a web server"
            )

        return None

    def is_closed_port(self, error):
        """A refused or unreachable port is a closed port, not an error.

        A `-r all` scan of a live host gets one of these for every closed
        port, so lumping them in with the error counter ended a four-row table
        with "65540 error(s) while scanning" and made a perfectly healthy scan
        look broken.
        """
        if isinstance(error, (ConnectionRefusedError, ConnectionResetError)):
            return True

        numero = getattr(error, "errno", None)
        if numero is None:
            try:
                numero = getattr(error.args[0], "errno", None)
            except Exception:
                numero = None

        # ECONNREFUSED, ENETUNREACH, ECONNRESET, EHOSTUNREACH, EHOSTDOWN, on
        # both the BSD and the Linux numbering
        return numero in (61, 111, 51, 101, 54, 104, 65, 113, 64, 112)

    def is_sip_request(self, resptext):
        """True when the payload is a SIP request, not a SIP response."""
        primera = resptext.replace("\r\n", "\n").split("\n")[0].strip()

        return re.match(r"^[A-Z]+\s+\S+\s+SIP/2\.0$", primera) is not None

    def process_sip_request(self, resptext, ip, rport, proto, sent=""):
        """A port that answers with a SIP request instead of a response.

        Two things look like this. Some hosts simply bounce the datagram back,
        so what arrives is our own OPTIONS -- a UDP reflector, which is worth
        knowing about on its own. Others (SBCs, proxies with an odd routing)
        really do send a request back. Either way the port answered something,
        and it used to end up in an "Empty response code" dump and be lost
        instead of making it into the table.
        """
        lines = resptext.replace("\r\n", "\n").split("\n")
        m = re.match(r"^([A-Z]+)\s+\S+\s+SIP/2\.0$", lines[0].strip())

        if not m:
            return False

        metodo = m.group(1)

        callid = ""
        ua = ""
        for linea in lines[1:]:
            if linea.strip() == "":
                break

            baja = linea.lower()
            if baja.startswith("call-id:") and callid == "":
                callid = linea.split(":", 1)[1].strip()
            if baja.startswith("user-agent:") and ua == "":
                ua = linea.split(":", 1)[1].strip()

        # our own Call-ID coming back means the host echoed the datagram: the
        # User-Agent in it is ours, so reporting it would be a lie
        eco = sent != "" and callid != "" and callid in sent

        if eco:
            response = "echo of our %s" % metodo
            ua = ""
            sip_type = "Reflector"
        else:
            response = "%s request" % metodo
            sip_type = "SIP request"

        line = "%s###%d###%s###%s###%s###%s###%s" % (
            ip,
            rport,
            proto,
            response,
            ua,
            sip_type,
            "",
        )

        if line not in self.found:
            self.found.append(line)

        if self.oifile != "" and ip not in self.ipsfound:
            self.ipsfound.append(ip)

        if self.verbose >= 1:
            print(
                f"{self.c.WHITE}Response <{response}> from {ip}:{str(rport)}/{proto}, a SIP request and not an answer"
            )

        return True

    def process_answer(self, resptext, ip, rport, proto, sent=""):
        """Record a SIP answer: used by every transport, UDP/TCP/TLS and the
        WebSocket ones, so a new transport does not have to copy the
        fingerprinting, the result row and the CVE lookup."""
        if resptext.startswith("HTTP/"):
            return self.process_http_answer(resptext, ip, rport, proto)

        headers = parse_message(resptext)

        # a request instead of an answer: an echo, or a host that really does
        # send one back. Either way the port is alive and belongs in the table
        if not headers or headers["response_code"] == "":
            if self.process_sip_request(resptext, ip, rport, proto, sent):
                return headers

        if headers and headers["response_code"] != "":
            sip_type = headers["type"]
            if self.method == "REGISTER":
                if headers["response_code"] == "405":
                    sip_type = "Device"
                if headers["response_code"] == "401":
                    sip_type = "Server"

            response = "%s %s" % (
                headers["response_code"],
                headers["response_text"],
            )

            try:
                fps = fingerprinting(
                    self.method, resptext, headers, self.verbose
                )
            except Exception:
                # a missing header must not discard the whole result
                fps = []

            fp = ""
            for f in fps:
                if fp == "":
                    fp = "%s" % f
                else:
                    fp += "/%s" % f

            if fp[0:1] == "/":
                fp = fp[1:]

            line = "%s###%d###%s###%s###%s###%s###%s" % (
                ip,
                rport,
                proto,
                response,
                headers["ua"],
                sip_type,
                fp,
            )
            self.found.append(line)

            if self.oifile != "":
                if ip not in self.ipsfound:
                    self.ipsfound.append(ip)

            if self.verbose == 1:
                if headers["ua"] != "":
                    print(
                        f"{self.c.WHITE}Response <{headers['response_code']} {headers['response_text']}> from {ip}:{str(rport)}/{proto} with User-Agent {headers['ua']}"
                    )
                else:
                    print(
                        f"{self.c.WHITE}Response <{headers['response_code']} {headers['response_text']}> from {ip}:{str(rport)}/{proto} without User-Agent"
                    )

            if headers["ua"] != "" and self.getcve == 1:
                val = check_model(headers["ua"], fp, sip_type, self.cvelist)
                if len(val) > 0:
                    for v in val:
                        if v not in self.cve:
                            self.cve.append(v)

        return headers

    def print(self):
        iplen = len("IP address")
        polen = len("Port")
        prlen = len("Proto")
        relen = len("Response")
        ualen = len("User-Agent")
        tplen = len("Type")
        fplen = len("Fingerprinting")

        for x in self.found:
            (ip, port, proto, res, ua, type, fp) = x.split("###")
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(res) > relen:
                relen = len(res)
            if len(ua) > ualen:
                ualen = len(ua)
            if len(type) > tplen:
                tplen = len(type)
            if self.fp == 1 and len(fp) > fplen:
                fplen = len(fp)

        if self.fp == 1:
            tlen = iplen + polen + prlen + relen + ualen + tplen + fplen + 20
        else:
            tlen = iplen + polen + prlen + relen + ualen + tplen + 17

        if self.fp == 1:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+{'-' * (fplen + 2)}+"
            )
        else:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+"
            )

        if self.fp == 1:
            print(
                f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} | {self.c.BWHITE}{'User-Agent'.ljust(ualen)}{self.c.WHITE} | {self.c.BWHITE}{'Type'.ljust(tplen)}{self.c.WHITE} | {self.c.BWHITE}{'Fingerprinting'.ljust(fplen)}{self.c.WHITE} |"
            )
        else:
            print(
                f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} | {self.c.BWHITE}{'User-Agent'.ljust(ualen)}{self.c.WHITE} | {self.c.BWHITE}{'Type'.ljust(tplen)}{self.c.WHITE} |"
            )

        if self.fp == 1:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+{'-' * (fplen + 2)}+"
            )
        else:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+"
            )

        if self.oifile != "" and len(self.ipsfound) > 0:
            with open(self.oifile, "a+") as fi:
                for x in self.ipsfound:
                    fi.write(x + "\n")

        # -oi only writes the address, losing the port and the protocol, which
        # is exactly what 'leak -f', 'exten -f' and 'rcrack -f' ask for. Its
        # format cannot change without breaking whoever uses it, so -ot writes
        # the same hosts as ip:port/proto and closes the chain
        if self.otfile != "" and len(self.found) > 0:
            write_targets(self.otfile, self.found)

        if self.ofile != "":
            f = open_log(self.ofile)

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (ip, port, proto, res, ua, type, fp) = x.split("###")

                if self.fp == 1:
                    print(
                        f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BBLUE}{res.ljust(relen)}{self.c.WHITE} | {self.c.BYELLOW}{ua.ljust(ualen)}{self.c.WHITE} | {self.c.BCYAN}{type.ljust(tplen)}{self.c.WHITE} | {self.c.BGREEN}{fp.ljust(fplen)}{self.c.WHITE} |"
                    )

                    if self.ofile != "":
                        f.write(
                            "%s:%s/%s => %s - %s (%s)\n"
                            % (ip, port, proto, res, ua, fp)
                        )
                else:
                    print(
                        f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BBLUE}{res.ljust(relen)}{self.c.WHITE} | {self.c.BYELLOW}{ua.ljust(ualen)}{self.c.WHITE} | {self.c.BCYAN}{type.ljust(tplen)}{self.c.WHITE} |"
                    )

                    if self.ofile != "":
                        f.write("%s:%s/%s => %s - %s\n" % (ip, port, proto, res, ua))

        if self.fp == 1:
            print(
                self.c.WHITE
                + "+"
                + "-" * (iplen + 2)
                + "+"
                + "-" * (polen + 2)
                + "+"
                + "-" * (prlen + 2)
                + "+"
                + "-" * (relen + 2)
                + "+"
                + "-" * (ualen + 2)
                + "+"
                + "-" * (tplen + 2)
                + "+"
                + "-" * (fplen + 2)
                + "+"
            )
        else:
            print(
                self.c.WHITE
                + "+"
                + "-" * (iplen + 2)
                + "+"
                + "-" * (polen + 2)
                + "+"
                + "-" * (prlen + 2)
                + "+"
                + "-" * (relen + 2)
                + "+"
                + "-" * (ualen + 2)
                + "+"
                + "-" * (tplen + 2)
                + "+"
            )

        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)

        errores = self.errors
        cerrados = self.closed

        # closed ports are only worth a line when asked for: on a live host a
        # -r all scan collects tens of thousands of them and they say nothing
        if self.closed > 0 and self.verbose >= 1:
            print(
                f"{self.c.YELLOW}[!] {str(self.closed)} closed port(s): refused or unreachable, not an error{self.c.WHITE}"
            )
            print(self.c.WHITE)

        self.closed = 0

        if self.errors > 0:
            print(
                f"{self.c.YELLOW}[!] {str(self.errors)} error(s) while scanning, hidden without {self.c.BYELLOW}-vv{self.c.WHITE}"
            )
            print(self.c.WHITE)
            self.errors = 0

        if self.httpfound == True:
            print(
                f"{self.c.YELLOW}[!] A `Web server` row answered HTTP, not SIP. If it is an Asterisk/Kamailio HTTP port, try {self.c.BYELLOW}-p ws{self.c.YELLOW} or {self.c.BYELLOW}-p wss{self.c.WHITE}"
            )
            print(self.c.WHITE)

        if self.fp == 1 and len(self.found) > 0:
            print(
                f"{self.c.YELLOW}[!] Fingerprinting is based on `To-tag` and other header values. The result may not be correct{self.c.WHITE}"
            )
            if self.method != "REGISTER":
                print(
                    f"{self.c.YELLOW}[!] Tip: You can try -m REGISTER to verify the fingerprinting result{self.c.WHITE}"
                )
            print(self.c.WHITE)

        if self.ofile != "":
            f.close()

        write_results(
            self.found,
            RESULT_FIELDS["scan"],
            "scan",
            jsonfile=self.ojson,
            csvfile=self.ocsv,
            meta={
                "target": self.ip if self.ip != "" else self.file,
                "port": self.rport,
                "proto": self.proto,
                "method": self.method,
                "elapsed": self.totaltime,
                "errors": errores,
                "closed": cerrados,
                "cves": self.cve_rows() if len(self.cve) > 0 else None,
                # None makes write_results drop the key, so with -tlsinfo off
                # the JSON comes out byte for byte what it was
                "tls": self.tls_rows() if len(self.tls) > 0 else None,
                "tls_findings": self.tls_finding_rows()
                if len(self.tlsfindings) > 0
                else None,
                "tls_versions": result_rows(
                    self.tlsver, RESULT_FIELDS["tls_versions"]
                )
                if len(self.tlsver) > 0
                else None,
            },
        )

        self.found.clear()

    def inspect_tls(self, sock_ssl, ipaddr, port, sni):
        """Reads the certificate of an already connected socket. Never raises
        out of here: a scan must not die because of a strange certificate."""
        # imported here and not at the top on purpose: sippts -up updates the
        # modules one by one, so a run that does not bring lib/tlsinfo.py yet
        # would otherwise stop `scan` from even starting. This way the only
        # thing lost is -tlsinfo
        try:
            from .lib import tlsinfo
        except ImportError:
            self.tlsinfo = 0
            self.tlsversions = 0

            print(
                f"{self.c.BRED}[!] -tlsinfo needs lib/tlsinfo.py, which is not installed. Update sippts with -up{self.c.WHITE}"
            )

            return

        info = tlsinfo.inspect_socket(sock_ssl, sni)
        clave = "%s###%s" % (ipaddr, port)

        if clave in self.tlsseen:
            return

        self.tlsseen.add(clave)

        # OpenSSL does the chain, with one extra connection, and only when
        # asked for: rebuilding path validation by hand goes wrong quietly
        confianza = tlsinfo.verify_chain(ipaddr, port, sni, 5)
        info["trust"] = confianza[0]

        self.tls.append(tlsinfo.fila(ipaddr, port, info))

        if self.tlsversions == 1:
            # one handshake per version, and only once per host:port thanks to
            # tlsseen: that is what keeps this out of the hot loop
            for nombre, estado, detalle in tlsinfo.versiones_aceptadas(
                ipaddr, port, 5
            ):
                self.tlsver.append(
                    "%s###%s###%s###%s###%s"
                    % (ipaddr, port, nombre, estado, detalle)
                )

                if estado == "accepted" and nombre in ("TLSv1.0", "TLSv1.1"):
                    self.tlsfindings.append(
                        "%s###%s###MEDIUM###TLS_OLD_VERSION###%s is accepted"
                        % (ipaddr, port, nombre)
                    )

        for severidad, codigo, detalle in tlsinfo.findings(info, sni, confianza):
            self.tlsfindings.append(
                "%s###%s###%s###%s###%s" % (ipaddr, port, severidad, codigo, detalle)
            )

    def tls_rows(self):
        return result_rows(self.tls, RESULT_FIELDS["scan_tls"])

    def tls_finding_rows(self):
        return result_rows(self.tlsfindings, RESULT_FIELDS["tls_findings"])

    def print_tls(self):
        ilen = len("IP address")
        plen = len("Port")
        vlen = len("TLS")
        clen = len("Cipher")
        klen = len("Key")
        elen = len("Expires")

        filas = []

        for x in self.tls:
            c = x.split("###")

            if len(c) < 14:
                continue

            filas.append((c[0], c[1], c[2], c[3], c[5], c[10], c[7], c[8], c[11], c[12]))

        for f in filas:
            ilen = max(ilen, len(f[0]))
            plen = max(plen, len(f[1]))
            vlen = max(vlen, len(f[2]))
            clen = max(clen, len(f[3]))
            klen = max(klen, len(f[4]))
            elen = max(elen, len(f[5]))

        raya = f"{self.c.WHITE}+{'-' * (ilen+2)}+{'-' * (plen+2)}+{'-' * (vlen+2)}+{'-' * (clen+2)}+{'-' * (klen+2)}+{'-' * (elen+2)}+"

        print(raya)
        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(ilen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(plen)}{self.c.WHITE} | {self.c.BWHITE}{'TLS'.ljust(vlen)}{self.c.WHITE} | {self.c.BWHITE}{'Cipher'.ljust(clen)}{self.c.WHITE} | {self.c.BWHITE}{'Key'.ljust(klen)}{self.c.WHITE} | {self.c.BWHITE}{'Expires'.ljust(elen)}{self.c.WHITE} |"
        )
        print(raya)

        for f in filas:
            print(
                f"{self.c.WHITE}| {self.c.BGREEN}{f[0].ljust(ilen)}{self.c.WHITE} | {self.c.BGREEN}{f[1].ljust(plen)}{self.c.WHITE} | {self.c.BMAGENTA}{f[2].ljust(vlen)}{self.c.WHITE} | {self.c.BCYAN}{f[3].ljust(clen)}{self.c.WHITE} | {self.c.BYELLOW}{f[4].ljust(klen)}{self.c.WHITE} | {self.c.BWHITE}{f[5].ljust(elen)}{self.c.WHITE} |"
            )

            if self.verbose >= 1:
                print(
                    f"{self.c.WHITE}|   {self.c.WHITE}subject: {f[6]}   issuer: {f[7]}"
                )

                if f[8] != "":
                    print(f"{self.c.WHITE}|   SAN: {f[8]}")

                print(f"{self.c.WHITE}|   sha256: {f[9]}")

        print(raya)
        print(self.c.WHITE)

        if len(self.tlsfindings) > 0:
            slen = len("Sev")
            flen = len("Finding")
            dlen = len("Detail")
            hallazgos = []

            for x in self.tlsfindings:
                c = x.split("###")

                if len(c) < 5:
                    continue

                hallazgos.append((c[0], c[1], c[2], c[3], c[4]))

            hilen = max([len(h[0]) for h in hallazgos] + [len("IP address")])
            hplen = max([len(h[1]) for h in hallazgos] + [len("Port")])
            slen = max([len(h[2]) for h in hallazgos] + [slen])
            flen = max([len(h[3]) for h in hallazgos] + [flen])
            dlen = max([len(h[4]) for h in hallazgos] + [dlen])

            raya2 = f"{self.c.WHITE}+{'-' * (hilen+2)}+{'-' * (hplen+2)}+{'-' * (slen+2)}+{'-' * (flen+2)}+{'-' * (dlen+2)}+"
            print(raya2)
            print(
                f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(hilen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(hplen)}{self.c.WHITE} | {self.c.BWHITE}{'Sev'.ljust(slen)}{self.c.WHITE} | {self.c.BWHITE}{'Finding'.ljust(flen)}{self.c.WHITE} | {self.c.BWHITE}{'Detail'.ljust(dlen)}{self.c.WHITE} |"
            )
            print(raya2)

            for h in hallazgos:
                color = (
                    self.c.BRED
                    if h[2] == "HIGH"
                    else self.c.BYELLOW
                    if h[2] == "MEDIUM"
                    else self.c.BCYAN
                )
                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{h[0].ljust(hilen)}{self.c.WHITE} | {self.c.BGREEN}{h[1].ljust(hplen)}{self.c.WHITE} | {color}{h[2].ljust(slen)}{self.c.WHITE} | {color}{h[3].ljust(flen)}{self.c.WHITE} | {self.c.WHITE}{h[4].ljust(dlen)}{self.c.WHITE} |"
                )

            print(raya2)
            print(self.c.WHITE)

        if len(self.tlsver) > 0:
            filas = []

            for x in self.tlsver:
                c = x.split("###")

                if len(c) >= 5:
                    filas.append((c[0], c[1], c[2], c[3], c[4]))

            a1 = max([len(f[0]) for f in filas] + [len("IP address")])
            a2 = max([len(f[1]) for f in filas] + [len("Port")])
            a3 = max([len(f[2]) for f in filas] + [len("Version")])
            a4 = max([len(f[3]) for f in filas] + [len("Status")])
            a5 = max([len(f[4]) for f in filas] + [len("Detail")])

            raya3 = f"{self.c.WHITE}+{'-' * (a1+2)}+{'-' * (a2+2)}+{'-' * (a3+2)}+{'-' * (a4+2)}+{'-' * (a5+2)}+"
            print(raya3)
            print(
                f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(a1)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(a2)}{self.c.WHITE} | {self.c.BWHITE}{'Version'.ljust(a3)}{self.c.WHITE} | {self.c.BWHITE}{'Status'.ljust(a4)}{self.c.WHITE} | {self.c.BWHITE}{'Detail'.ljust(a5)}{self.c.WHITE} |"
            )
            print(raya3)

            for f in filas:
                color = (
                    self.c.BYELLOW
                    if f[3] == "accepted" and f[2] in ("TLSv1.0", "TLSv1.1")
                    else self.c.BGREEN
                    if f[3] == "accepted"
                    else self.c.WHITE
                )
                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{f[0].ljust(a1)}{self.c.WHITE} | {self.c.BGREEN}{f[1].ljust(a2)}{self.c.WHITE} | {self.c.BMAGENTA}{f[2].ljust(a3)}{self.c.WHITE} | {color}{f[3].ljust(a4)}{self.c.WHITE} | {self.c.WHITE}{f[4].ljust(a5)}{self.c.WHITE} |"
                )

            print(raya3)
            print(self.c.WHITE)
            print(
                f"{self.c.YELLOW}[!] 'untested' means this OpenSSL cannot offer that version, NOT that the server has it disabled{self.c.WHITE}"
            )

        print(
            f"{self.c.YELLOW}[!] A self-signed certificate on an internal SIP trunk is not a finding by itself. SSLv2/SSLv3 cannot be tested: this OpenSSL does not offer them\n{self.c.WHITE}"
        )

    def cve_rows(self):
        # 'type' is really the CVE description. The key is kept so that an
        # existing jq '.cves[].type' does not break, and 'description' is
        # added with the same value: it goes away in 5.0. RESULT_FIELDS is
        # left alone on purpose, so the CSV stays byte for byte what it was
        rows = result_rows(self.cve, RESULT_FIELDS["scan_cve"])

        for row in rows:
            row["description"] = row["type"]
            # split so a consumer does not have to parse "HIGH|8.8|3.1"
            row["cvss_severity"] = cvss_severity(row["cvss"])
            row["cvss_score"] = cvss_score(row["cvss"])
            row["cvss_version"] = cvss_version(row["cvss"])

        return rows

    def print_cve(self):
        def campos(x):
            """Never unpack into a fixed number of names: it used to be
            (de, ve, cv, ty, ur) = x.split("###"), so the day the list grew a
            column every scan that found something died with ValueError right
            at the end, after all the work"""
            c = x.split("###")

            return [c[i] if i < len(c) else "" for i in range(6)]

        delen = len("Device")
        velen = len("Version")
        cvlen = len("CVE")
        # the 4th column of cve.csv is the CVE description, not a type
        tylen = len("Description")
        urlen = len("URL")
        cslen = len("CVSS")

        filas = []

        for x in self.cve:
            (de, ve, cv, ty, ur, cs) = campos(x)
            texto = cvss_text(cs)
            filas.append((de, ve, cv, ty, ur, texto, cvss_severity(cs)))
            delen = max(delen, len(de))
            velen = max(velen, len(ve))
            cvlen = max(cvlen, len(cv))
            tylen = max(tylen, len(ty))
            urlen = max(urlen, len(ur))
            cslen = max(cslen, len(texto))

        tlen = delen + velen + cvlen + tylen + urlen + cslen + 17

        raya = f"{self.c.WHITE}+{'-' * (delen+2)}+{'-' * (velen+2)}+{'-' * (cvlen+2)}+{'-' * (cslen+2)}+{'-' * (tylen+2)}+{'-' * (urlen+2)}+"

        print(f"{self.c.WHITE}+{'-' * tlen}+")
        print(
            f"{self.c.WHITE}| {self.c.BYELLOW}{'Potential known vulnerabilities'.ljust(tlen-2)}{self.c.WHITE} |"
        )
        print(raya)
        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'Device'.ljust(delen)}{self.c.WHITE} | {self.c.BWHITE}{'Version'.ljust(velen)}{self.c.WHITE} | {self.c.BWHITE}{'CVE'.ljust(cvlen)}{self.c.WHITE} | {self.c.BWHITE}{'CVSS'.ljust(cslen)}{self.c.WHITE} | {self.c.BWHITE}{'Description'.ljust(tylen)}{self.c.WHITE} | {self.c.BWHITE}{'URL'.ljust(urlen)}{self.c.WHITE} |"
        )
        print(raya)

        if self.ofile != "":
            f = open_log(self.ofile)

        if len(self.cve) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            if self.ofile != "":
                f.write("-----\n")

            colores = {
                "CRITICAL": self.c.BMAGENTA,
                "HIGH": self.c.BRED,
                "MEDIUM": self.c.BYELLOW,
                "LOW": self.c.BCYAN,
            }

            for de, ve, cv, ty, ur, texto, sev in filas:
                color = colores.get(sev, self.c.WHITE)

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{de.ljust(delen)}{self.c.WHITE} | {self.c.BMAGENTA}{ve.ljust(velen)}{self.c.WHITE} | {self.c.BYELLOW}{cv.ljust(cvlen)}{self.c.WHITE} | {color}{texto.ljust(cslen)}{self.c.WHITE} | {self.c.BCYAN}{ty.ljust(tylen)}{self.c.WHITE} | {self.c.BBLUE}{ur.ljust(urlen)}{self.c.WHITE} |"
                )

                if self.ofile != "":
                    f.write(
                        "%s %s => %s - %s - %s - %s\n" % (de, ve, cv, texto, ty, ur)
                    )

            if self.ofile != "":
                f.write("-----\n")

        print(raya)
        print(self.c.WHITE)

        if any(fila[5].endswith("v2") for fila in filas):
            print(
                f"{self.c.YELLOW}[!] A score marked v2 comes from CVSS v2, whose scale is not the one of v3 and has no CRITICAL level{self.c.WHITE}"
            )
            print(self.c.WHITE)

        if self.ofile != "":
            f.close()

        self.cve.clear()
