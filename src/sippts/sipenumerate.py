#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import re
import socket
import sys
import ssl
import time
from .lib.functions import (
    create_message,
    close_sockets,
    bind_local_port,
    parse_message,
    fingerprinting,
    format_time,
    write_results,
    RESULT_FIELDS,
    get_free_port,
    generate_random_string,
)
from .lib.wsclient import ws_connect, ws_error_text, is_timeout
from .lib.color import Color
from .lib.logos import Logo
from concurrent.futures import ThreadPoolExecutor


class SipEnumerate:
    def __init__(self):
        self.nocolor = ""
        self.ojson = ""
        self.ocsv = ""
        self.ip = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.path = ""
        self.httpfound = False
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.from_tag = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.user_agent = "pplsip"
        self.header = ""
        self.digest = ""
        self.verbose = 0
        self.timeout = 5

        self.totaltime = 0
        self.quit = False

        self.found = []
        # what the server advertises, kept apart from self.found so the main
        # table does not change shape. list.append is atomic under the GIL,
        # which is what self.found already relies on with 20 threads
        self.capsfound = []

        self.c = Color()

    def start(self):
        # -nocolor has to be applied before anything is printed, the logo
        # included, or those lines keep their escape codes
        try:
            self.nocolor = int(self.nocolor)
        except (TypeError, ValueError):
            self.nocolor = 0

        if self.nocolor == 1:
            self.c.ansy()

        # from sippts-gui it arrives as text and the comparison against 5060
        # below never matched, so -p TLS did not switch to the default 5061
        try:
            self.rport = int(self.rport)
        except (TypeError, ValueError):
            self.rport = 5060

        # from sippts-gui it arrives as text, and settimeout() then raised
        # TypeError inside a bare except: the module reported a socket error
        # that never happened
        try:
            self.timeout = int(self.timeout)
        except (TypeError, ValueError):
            self.timeout = 5

        # reset the stop flag: after a Ctrl+C the object kept it set, so from
        # sippts-gui (where the module instance is reused) every later run
        # did nothing at all
        self.quit = False

        supported_protos = ["UDP", "TCP", "TLS", "WS", "WSS"]
        supported_methods = [
            "REGISTER",
            "SUBSCRIBE",
            "NOTIFY",
            "PUBLISH",
            "MESSAGE",
            "INVITE",
            "OPTIONS",
            "ACK",
            "CANCEL",
            "BYE",
            "PRACK",
            "INFO",
            "REFER",
            "UPDATE",
        ]

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        self.proto = self.proto.upper()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == "TLS":
            self.rport = 5061

        # check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        logo = Logo("sipenumerate", self.nocolor)
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] IP address: {self.c.GREEN}{str(self.ip)}{self.c.WHITE}:{self.c.GREEN}{self.rport}{self.c.WHITE}/{self.c.GREEN}{self.proto}"
        )
        if self.proto in ("WS", "WSS") and self.path != "":
            print(f"{self.c.BWHITE}[✓] WS path: {self.c.GREEN}{self.path}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        if self.domain != "":
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
        if self.from_tag != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From Tag: {self.c.GREEN}{self.from_tag}"
            )
        if self.to_name != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Name: {self.c.GREEN}{self.to_name}"
            )
        if self.to_user != "100":
            print(
                f"{self.c.BWHITE}[✓] Customized To User: {self.c.GREEN}{self.to_user}"
            )
        if self.to_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Domain: {self.c.GREEN}{self.to_domain}"
            )
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )

        print(self.c.WHITE)

        if self.host != "" and self.domain == "":
            self.domain = self.host
        if self.domain == "":
            self.domain = self.ip
        if not self.from_domain or self.from_domain == "":
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == "":
            self.to_domain = self.domain

        if self.contact_domain == "":
            self.contact_domain = "10.0.0.1"

        if self.proxy != "":
            self.route = "<sip:%s;lr>" % self.proxy

        start = time.time()

        with ThreadPoolExecutor(max_workers=20) as executor:
            for j, method in enumerate(supported_methods):
                if self.quit == False:
                    executor.submit(self.send, method)

        end = time.time()
        self.totaltime = int(end - start)

        self.print()

    def send(self, method):
        if self.quit == False:
            if self.proto in ("WS", "WSS"):
                # SIP over WebSocket (RFC 7118): handshake and framing are done
                # by the shared client, the answers end in the same table
                return self.send_ws(method)

            try:
                if self.proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(f"{self.c.RED}Failed to create socket")
                print(self.c.WHITE)
                sys.exit(1)

            sock_ssl = None
            bind = "0.0.0.0"
            lport = bind_local_port(sock, bind)

            if lport == 0:
                sock.close()
                print(f"{self.c.RED}Failed to bind a local port")
                print(self.c.WHITE)
                return

            if self.proxy == "":
                host = (str(self.ip), int(self.rport))
            else:
                if self.proxy.find(":") > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(":")
                else:
                    proxy_ip = self.proxy
                    proxy_port = "5060"

                host = (str(proxy_ip), int(proxy_port))

            try:
                sock.settimeout(self.timeout)

                if self.proto == "TCP":
                    sock.connect(host)

                if self.proto == "TLS":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.load_default_certs()

                    sock_ssl = context.wrap_socket(sock, server_hostname=str(host[0]))
                    sock_ssl.connect(host)
            except:
                print(f"{self.c.RED}Socket connection error")
                print(self.c.WHITE)
                sys.exit()

            msg = self.build_message(method, lport)

            if self.verbose == 1:
                print(
                    f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                )
                print(f"{self.c.YELLOW}{msg}")

            if self.proto == "TLS":
                recv = lambda: sock_ssl.recv(4096)
            else:
                recv = lambda: sock.recv(4096)

            try:
                if self.proto == "TLS":
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)

                self.collect_answers(method, recv)
            except KeyboardInterrupt:
                print(f"{self.c.RED}\nYou pressed Ctrl+C!{self.c.WHITE}")
                self.quit = True
            except socket.timeout:
                print(
                    f"{self.c.BGREEN}{method}{self.c.RED} => Timeout error{self.c.WHITE}"
                )
                line = "%s###Timeout######" % method
                self.found.append(line)
                pass
            except:
                # the stray + made this handler raise TypeError, so the error
                # was never reported and the row never reached the table
                print(f"{self.c.BGREEN}{method}{self.c.RED} => Error{self.c.WHITE}")
                line = "%s###Error######" % method
                self.found.append(line)
                pass

            close_sockets(sock, sock_ssl)



    def send_ws(self, method):
        """Enumerate one method over a SIP WebSocket."""
        conn = None
        lport = get_free_port()

        if self.contact_domain == "":
            # RFC 7118: a WebSocket client has no address of its own
            self.contact_domain = "%s.invalid" % generate_random_string(12, 12, "hex")

        msg = self.build_message(method, lport)

        try:
            conn, url = ws_connect(
                self.proto,
                self.ip,
                self.rport,
                self.path,
                timeout=self.timeout,
                sni=self.domain if self.domain not in ("", None) else str(self.ip),
            )
        except Exception as error:
            print(
                f"{self.c.BGREEN}{method}{self.c.RED} => {ws_error_text(error)}{self.c.WHITE}"
            )
            self.found.append("%s###Error######" % method)

            return

        if self.verbose == 1:
            print(f"{self.c.BWHITE}[+] Sending to {url} ...")
            print(f"{self.c.YELLOW}{msg}")

        try:
            conn.settimeout(self.timeout)
            conn.send(msg)

            self.collect_answers(method, conn.recv)
        except KeyboardInterrupt:
            print(f"{self.c.RED}\nYou pressed Ctrl+C!{self.c.WHITE}")
            self.quit = True
        except Exception as error:
            if is_timeout(error):
                print(
                    f"{self.c.BGREEN}{method}{self.c.RED} => Timeout error{self.c.WHITE}"
                )
                self.found.append("%s###Timeout######" % method)
            else:
                print(
                    f"{self.c.BGREEN}{method}{self.c.RED} => {ws_error_text(error)}{self.c.WHITE}"
                )
                self.found.append("%s###Error######" % method)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def build_message(self, method, lport):
        """The request for one method, shared by every transport."""
        from_user = self.from_user
        to_user = self.to_user

        if method == "REGISTER":
            if self.to_user == "100" and self.from_user != "100":
                from_user = self.from_user
                to_user = self.from_user
            if self.to_user != "100" and self.from_user == "100":
                from_user = self.to_user
                to_user = self.to_user

        msg = create_message(
            method,
            "",
            self.contact_domain,
            from_user,
            self.from_name,
            self.domain,
            to_user,
            self.to_name,
            self.domain,
            self.proto,
            self.domain,
            self.user_agent,
            lport,
            "",
            "",
            self.from_tag,
            "1",
            "",
            self.digest,
            1,
            "",
            0,
            "",
            self.route,
            "",
            "",
            self.header,
            1,
        )

        return msg


    def collect_answers(self, method, recv):
        """Read the answers to one method and record the row.

        recv() returns the next answer (bytes or str), or something empty when
        the peer closed: the same loop then works over a raw socket and over a
        WebSocket, which has no recv(4096).
        """
        rescode = "100"
        resdata = ""
        resdataua = ""
        ua = "Not found"
        headers = None
        tries = 0

        # a server that answers something unparseable (or a TCP peer
        # that closes the connection, where recv() returns b'' right
        # away) left rescode at 100 and this loop spinning forever
        while rescode[:1] == "1" and tries < 10:
            tries += 1

            resp = recv()

            if not resp:
                break

            if isinstance(resp, (bytes, bytearray)):
                resp = resp.decode("utf-8", errors="replace")

            # a port that answers HTTP is a web server, not a SIP server with
            # an empty response code: say so and do not fingerprint it
            if resp.startswith("HTTP/"):
                self.httpfound = True
                status = resp.replace("\r\n", "\n").split("\n")[0].strip()
                resdata = re.sub(r"^HTTP/[\d.]+\s+", "HTTP ", status)
                ua = ""

                for linea in resp.replace("\r\n", "\n").split("\n")[1:]:
                    if linea.strip() == "":
                        break

                    if linea.lower().startswith("server:"):
                        ua = linea.split(":", 1)[1].strip()
                        break

                print(
                    f"{self.c.BCYAN}{method}{self.c.WHITE} => {self.c.YELLOW}{resdata}{self.c.WHITE} (Server: {ua})"
                )
                self.found.append(
                    "%s###%s###%s###%s" % (method, resdata, ua, "Web server")
                )

                return

            headers = parse_message(resp)

            if headers:
                rescode = headers["response_code"]
                restext = headers["response_text"]

                ua = headers["ua"]
                if ua == "":
                    ua = "Not found"

                if resdata != "":
                    resdata = resdata + " / "
                    resdataua = resdataua + self.c.WHITE + " / "
                resdata = resdata + "%s %s" % (rescode, restext)
                resdataua = (
                    resdataua
                    + self.c.YELLOW
                    + "%s %s" % (rescode, restext)
                    + self.c.WHITE
                    + " (User-Agent: %s)" % ua
                )

        if self.verbose == 1:
            print(
                f"{self.c.BWHITE}[+] Receiving from {self.ip}:{str(self.rport)} ..."
            )
            print(f"{self.c.GREEN}{resp}")
        else:
            print(f"{self.c.BCYAN}{method}{self.c.WHITE} => {resdataua}")

        try:
            fps = fingerprinting(method, resp, headers, self.verbose)
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

        for clave in ("allow", "supported", "allow_events"):
            if headers.get(clave, "") != "":
                self.capsfound.append(
                    "%s###%s###%s" % (method, clave, headers[clave])
                )

        line = "%s###%s###%s###%s" % (method, resdata, ua, fp)
        self.found.append(line)

    def print(self):
        mlen = len("Method")
        rlen = len("Response")
        ualen = len("User-Agent")
        fplen = len("Fingerprinting")

        for x in self.found:
            (m, r, ua, fp) = x.split("###")
            if len(m) > mlen:
                mlen = len(m)
            if len(r) > rlen:
                rlen = len(r)
            if len(ua) > ualen:
                ualen = len(ua)
            if len(fp) > fplen:
                fplen = len(fp)

        tlen = mlen + rlen + ualen + fplen + 11

        print(self.c.WHITE)
        print(
            f"{self.c.WHITE}+{'-' * (mlen + 2)}+{'-' * (rlen + 2)}+{'-' * (ualen + 2)}+{'-' * (fplen + 2)}+"
        )

        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'Method'.ljust(mlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(rlen)}{self.c.WHITE} | {self.c.BWHITE}{'User-Agent'.ljust(ualen)}{self.c.WHITE} | {self.c.BWHITE}{'Fingerprinting'.ljust(fplen)}{self.c.WHITE} |"
        )

        print(
            f"{self.c.WHITE}+{'-' * (mlen + 2)}+{'-' * (rlen + 2)}+{'-' * (ualen + 2)}+{'-' * (fplen + 2)}+"
        )

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (m, r, ua, fp) = x.split("###")

                if r == "Timeout" or r == "Error":
                    print(
                        f"{self.c.WHITE}| {self.c.BCYAN}{m.ljust(mlen)}{self.c.WHITE} | {self.c.BRED}{r.ljust(rlen)}{self.c.WHITE} | {self.c.BYELLOW}{ua.ljust(ualen)}{self.c.WHITE} | {self.c.BMAGENTA}{fp.ljust(fplen)}{self.c.WHITE} |"
                    )
                else:
                    print(
                        f"{self.c.WHITE}| {self.c.BCYAN}{m.ljust(mlen)}{self.c.WHITE} | {self.c.BGREEN}{r.ljust(rlen)}{self.c.WHITE} | {self.c.BYELLOW}{ua.ljust(ualen)}{self.c.WHITE} | {self.c.BMAGENTA}{fp.ljust(fplen)}{self.c.WHITE} |"
                    )

        print(
            f"{self.c.WHITE}+{'-' * (mlen + 2)}+{'-' * (rlen + 2)}+{'-' * (ualen + 2)}+{'-' * (fplen + 2)}+"
        )
        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{format_time(self.totaltime)}{self.c.WHITE}"
        )
        print(self.c.WHITE)

        if self.httpfound == True:
            print(
                f"{self.c.YELLOW}[!] This port answered HTTP, not SIP. If it is an Asterisk/Kamailio HTTP port, try {self.c.BYELLOW}-p ws{self.c.YELLOW} or {self.c.BYELLOW}-p wss{self.c.WHITE}"
            )
            print(self.c.WHITE)
        elif len(self.found) > 0:
            print(
                f"{self.c.YELLOW}[!] Fingerprinting is based on `To-tag` and other header values. The result may not be correct\n{self.c.WHITE}"
            )

        capacidades = self.capabilities()

        if capacidades != {}:
            self.print_capabilities(capacidades)

        write_results(
            self.found,
            RESULT_FIELDS["enumerate"],
            "enumerate",
            jsonfile=self.ojson,
            csvfile=self.ocsv,
            meta={
                "target": self.ip,
                "port": self.rport,
                "proto": self.proto,
                "elapsed": self.totaltime,
                # only the JSON carries meta, so RESULT_FIELDS and the CSV stay
                # exactly as they were
                "capabilities": {
                    k: sorted(v) for k, v in capacidades.items()
                }
                if capacidades != {}
                else None,
            },
        )

        self.found.clear()

    def capabilities(self):
        """The union of what the server advertised, header by header."""
        capacidades = {}

        for linea in self.capsfound:
            partes = linea.split("###")

            if len(partes) < 3:
                continue

            valores = [v.strip() for v in partes[2].split(",") if v.strip() != ""]
            capacidades.setdefault(partes[1], set()).update(valores)

        return capacidades

    def print_capabilities(self, capacidades):
        etiquetas = {
            "allow": "Allow",
            "supported": "Supported",
            "allow_events": "Allow-Events",
        }
        filas = []

        for clave in ("allow", "supported", "allow_events"):
            if clave in capacidades:
                filas.append((etiquetas[clave], ", ".join(sorted(capacidades[clave]))))

        # the point of the table: what the server says it takes versus what it
        # actually answered. A method advertised in Allow that never answered
        # is the interesting one
        anunciados = set(m.upper() for m in capacidades.get("allow", set()))

        # a method that answers 405 or 501 is NOT supported, whatever Allow
        # says: counting it as answered would hide the contradiction, which is
        # the interesting part
        aceptados = set()

        for x in self.found:
            partes = x.split("###")

            if len(partes) < 2:
                continue

            codigo = partes[1].split(" ")[0]

            if codigo in ("405", "501") or partes[1] in ("Timeout", "Error"):
                continue

            aceptados.add(partes[0].upper())

        hlen = max([len(f[0]) for f in filas] + [len("Header")])
        vlen = max([len(f[1]) for f in filas] + [len("Values")])

        print(
            f"{self.c.WHITE}+{'-' * (hlen + 2)}+{'-' * (vlen + 2)}+"
        )
        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'Header'.ljust(hlen)}{self.c.WHITE} | {self.c.BWHITE}{'Values'.ljust(vlen)}{self.c.WHITE} |"
        )
        print(
            f"{self.c.WHITE}+{'-' * (hlen + 2)}+{'-' * (vlen + 2)}+"
        )

        for nombre, valor in filas:
            print(
                f"{self.c.WHITE}| {self.c.BGREEN}{nombre.ljust(hlen)}{self.c.WHITE} | {self.c.BCYAN}{valor.ljust(vlen)}{self.c.WHITE} |"
            )

        print(
            f"{self.c.WHITE}+{'-' * (hlen + 2)}+{'-' * (vlen + 2)}+"
        )
        print(self.c.WHITE)

        solo_anunciados = sorted(anunciados - aceptados)
        solo_aceptados = sorted(aceptados - anunciados)

        if solo_anunciados != []:
            print(
                f"{self.c.BWHITE}Advertised in Allow but rejected or unanswered: {self.c.BYELLOW}{', '.join(solo_anunciados)}{self.c.WHITE}"
            )

        if solo_aceptados != []:
            print(
                f"{self.c.BWHITE}Accepted but not advertised in Allow: {self.c.BYELLOW}{', '.join(solo_aceptados)}{self.c.WHITE}"
            )

        if solo_anunciados != [] or solo_aceptados != []:
            print(self.c.WHITE)
