import random
from random import randint
from datetime import datetime, timezone
import ipaddress
import re
import netifaces
import socket
import subprocess
import struct
import os
import sys
import csv
import json
import hashlib
import platform


BRED = "\033[1;31;20m"
RED = "\033[0;31;20m"
BRED_BLACK = "\033[1;30;41m"
RED_BLACK = "\033[0;30;41m"
BGREEN = "\033[1;32;20m"
GREEN = "\033[0;32;20m"
BGREEN_BLACK = "\033[1;30;42m"
GREEN_BLACK = "\033[0;30;42m"
BYELLOW = "\033[1;33;20m"
YELLOW = "\033[0;33;20m"
BBLUE = "\033[1;34;20m"
BLUE = "\033[0;34;20m"
BMAGENTA = "\033[1;35;20m"
MAGENTA = "\033[0;35;20m"
BCYAN = "\033[1;36;20m"
CYAN = "\033[0;36;20m"
BWHITE = "\033[1;37;20m"
WHITE = "\033[0;37;20m"


def get_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    _, port = sock.getsockname()
    sock.close()

    return port


def system_call(command):
    p = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
    return p.stdout.read()


def searchInterface():
    ifaces = netifaces.interfaces()
    networkInterface = ""

    try:
        local_ip = get_machine_default_ip()
    except OSError:
        return networkInterface

    for iface in ifaces:
        data = netifaces.ifaddresses(iface)
        if str(data).find(local_ip) != -1:
            networkInterface = iface

    return networkInterface


def ping(host, time="1"):
    # parameter = '-n' if platform.system().lower() == 'windows' else '-c'
    response = subprocess.run(
        ["ping", "-t", "1", "-c", "1", "-W", str(time), str(host)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if response.returncode == 0:
        return True
    else:
        return False


def get_default_gateway_mac():
    return system_call(
        "route -n get default | grep 'gateway' | awk '{print $2}'"
    ).decode()


def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))


def get_machine_default_ip(type="ip"):
    """
    Return the default gateway IP for the machine.

    It used to return None when there was no default route, and the callers,
    which expect an exception to suggest -local-ip, silently put the string
    'None' inside the SIP messages.
    """
    gateways = netifaces.gateways()
    defaults = gateways.get("default")
    if not defaults:
        raise OSError("no default gateway")

    def default_ip(family):
        gw_info = defaults.get(family)
        if not gw_info:
            return
        addresses = netifaces.ifaddresses(gw_info[1]).get(family)
        if addresses:
            if type == "mask":
                return addresses[0]["netmask"]
            else:
                return addresses[0]["addr"]

    address = default_ip(netifaces.AF_INET) or default_ip(netifaces.AF_INET6)

    if not address:
        raise OSError("no address on the default interface")

    return address


def _set_mac_iproute(value):
    """
    Enable or disable IP forwarding on macOS.

    It used to call exec() with the command line, which Python read as source
    code and always failed with SyntaxError: forwarding was never touched.
    """
    cmd = ["sysctl", "-w", "net.inet.ip.forwarding=%s" % value]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )

        if result.returncode != 0:
            raise OSError(result.stderr.strip())

        return True
    except Exception as error:
        print(
            f"{RED}\nError running {' '.join(cmd)} ({error})."
            f" Please execute it manually with sudo{WHITE}"
        )

        return False


def _enable_mac_iproute():
    return _set_mac_iproute(1)


def _disable_mac_iproute():
    return _set_mac_iproute(0)


def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """

    file_path = "/proc/sys/net/ipv4/ip_forward"

    try:
        with open(file_path) as f:
            # the file holds text: comparing it with the number never matched
            if f.read().strip() == "1":
                # already enabled
                return True

        with open(file_path, "w") as f:
            print(1, file=f)

        return True
    except OSError as error:
        print(f"{RED}\nError writing {file_path} ({error}){WHITE}")

        return False


def _disable_linux_iproute():
    """
    Disables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"

    try:
        with open(file_path) as f:
            # the file holds text: comparing it with the number never matched
            if f.read().strip() == "0":
                # already disabled
                return True

        with open(file_path, "w") as f:
            print(0, file=f)

        return True
    except OSError as error:
        print(f"{RED}\nError writing {file_path} ({error}){WHITE}")

        return False


# def _enable_windows_iproute():
#     """
#     Enables IP route (IP Forwarding) in Windows
#     """
#     from services import WService
#     # enable Remote Access service
#     service = WService("RemoteAccess")
#     service.start()


def disable_ip_route(verbose=1):
    """
    Disables IP forwarding
    """
    if verbose > 0:
        print(f"{YELLOW}[!] Disabling IP Routing...{WHITE}")

    # outside the verbose check: with -v 0 the forwarding was never touched
    ops = platform.system()
    done = False

    if ops == "Darwin":
        done = _disable_mac_iproute()
    elif ops == "Linux":
        done = _disable_linux_iproute()

    if verbose > 0:
        if done:
            print(f"{YELLOW}[!] IP Routing disabled.\n{WHITE}")
        else:
            print(f"{RED}[!] IP Routing could not be disabled\n{WHITE}")

    return done


def enable_ip_route(verbose=1):
    """
    Enables IP forwarding
    """
    if verbose > 0:
        print(f"{BWHITE}[!] Enabling IP Routing...{WHITE}")

    # outside the verbose check: with -v 0 the forwarding was never touched
    ops = platform.system()
    done = False

    if ops == "Darwin":
        done = _enable_mac_iproute()
    elif ops == "Linux":
        done = _enable_linux_iproute()

    if verbose > 0:
        if done:
            print(f"{BWHITE}[!] IP Routing enabled\n{WHITE}")
        else:
            # without forwarding the victim traffic is dropped, not relayed
            print(
                f"{RED}[!] IP Routing is NOT enabled: the traffic of the"
                f" victims will be dropped instead of relayed\n{WHITE}"
            )

    return done


def ip2long(ip):
    """
    Convert an IP string to long
    """
    try:
        # First, try to handle IPv4 addresses
        packedIP = socket.inet_aton(ip)
        return int.from_bytes(packedIP, 'big')
    except OSError:
        # If it's not IPv4, assume it's IPv6 and try to handle that
        packedIP = socket.inet_pton(socket.AF_INET6, ip)
        return int.from_bytes(packedIP, 'big')


def long2ip(ip):
    try:
        # Try to handle IPv4 addresses first
        return str(socket.inet_ntoa(struct.pack("!L", ip)))
    except struct.error:
        # If the IP is too large for IPv4, assume it's IPv6
        packed_ip = ip.to_bytes(16, byteorder='big')  # Assuming the `ip` is in integer form
        return socket.inet_ntop(socket.AF_INET6, packed_ip)


# Maximum number of addresses a single target item may expand to (a /8)
MAX_TARGET_ADDRESSES = 2**24


def expand_targets(target):
    """
    Expand a target specification into a list of IP addresses.

    `target` is a comma separated list and every item can be:
      - an IP address         192.168.0.10
      - a hostname            mysipserver.com
      - a network             192.168.0.0/24  (network and broadcast are skipped)
      - a range of addresses  192.168.0.10-192.168.0.20  or  192.168.0.10-20

    Each item is expanded on its own, so 10.0.0.1,10.0.5.1 gives those two
    addresses and not the 1281 addresses between them.

    Returns a tuple (ips, names):
      ips    ordered list of addresses, without duplicates
      names  items that were given as a hostname, so the caller can keep using
             the name as the SIP domain instead of the resolved address

    Raises ValueError, with a message ready to be shown to the user, when an
    item cannot be expanded.
    """
    ips = []
    names = []
    seen = set()

    def add(addr):
        addr = str(addr)
        if addr not in seen:
            seen.add(addr)
            ips.append(addr)

    for item in str(target).split(","):
        item = item.strip()

        if item == "":
            continue

        # range of addresses: 192.168.0.10-192.168.0.20 or 192.168.0.10-20
        m = re.fullmatch(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*-\s*([0-9.]+)", item)
        if m:
            (first, last) = (m.group(1), m.group(2))

            if last.find(".") < 0:
                # only the last octet of the end address was given
                last = "%s.%s" % (first.rsplit(".", 1)[0], last)

            try:
                ipini = int(ip2long(first))
                ipend = int(ip2long(last))
            except OSError:
                raise ValueError("Invalid address range %s" % item)

            if ipend < ipini:
                raise ValueError(
                    "Invalid address range %s: %s is lower than %s" % (item, last, first)
                )
            if ipend - ipini + 1 > MAX_TARGET_ADDRESSES:
                raise ValueError("Address range %s is too big" % item)

            for i in range(ipini, ipend + 1):
                add(long2ip(i))

            continue

        # hostname
        name = ""
        if item.find("/") < 0:
            try:
                ipaddress.ip_address(item)
            except ValueError:
                try:
                    name = item
                    item = socket.gethostbyname(item)
                except socket.error:
                    raise ValueError("Cannot resolve host %s" % name)

        # single address or network
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError("Invalid target %s" % item)

        if net.num_addresses > MAX_TARGET_ADDRESSES:
            raise ValueError("Network %s is too big" % net)

        for h in net.hosts():
            add(h)

        if name != "":
            names.append(name)

    return (ips, names)


def host_sort_key(line):
    """
    Sort key for result lines that start with an address (address###port###...).

    Sorting them as text puts 10.0.0.100 before 10.0.0.9, so the address is
    compared as a number and the port as an integer.
    """
    aux = str(line).split("###")

    try:
        ip = ipaddress.ip_address(aux[0])
        addr = (ip.version, int(ip))
    except (ValueError, IndexError):
        addr = (0, 0)

    try:
        port = int(aux[1])
    except (ValueError, IndexError):
        port = 0

    return (addr, port, str(line))


class _NoChildWatcher:
    """
    Stand-in for the asyncio child watchers, removed in Python 3.14.

    They are no longer needed (asyncio reaps its own subprocesses since 3.12),
    but pyshark 0.6 still asks for one.
    """

    def attach_loop(self, loop):
        pass

    def add_child_handler(self, pid, callback, *args):
        pass

    def remove_child_handler(self, pid):
        return True

    def is_active(self):
        return True

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def pyshark_compat():
    """
    Make pyshark 0.6 usable on current Python versions.

    0.6 is its last release and it (a) asks for an event loop of the current
    thread, which raises RuntimeError since Python 3.12 when there is none,
    and (b) calls asyncio.set_child_watcher(), removed in 3.14. Without this,
    dump, pcapdump and sniff die before reading a single packet.
    """
    import asyncio

    try:
        asyncio.get_event_loop_policy().get_event_loop()
    except (RuntimeError, DeprecationWarning):
        asyncio.set_event_loop(asyncio.new_event_loop())

    if not hasattr(asyncio, "set_child_watcher"):
        watcher = _NoChildWatcher()

        asyncio.SafeChildWatcher = _NoChildWatcher
        asyncio.set_child_watcher = lambda w: None
        asyncio.get_child_watcher = lambda: watcher


class _NullLog:
    """Stands in for a log file that could not be opened, so a wrong path with
    -o does not throw away the results already gathered."""

    def write(self, data):
        pass

    def close(self):
        pass


# Last resort only: the real version lives in the 'version' file of the
# repository, which is also the one github serves for the -up check.
_FALLBACK_VERSION = "4.1.2"


def version_file():
    """
    Path of the file holding the version number.

    'version' at the root of the repository is the one the author edits and
    the one github serves. setup.py copies it into the package as
    data/version.txt so an installed copy finds it too. Resolved the same way
    as cve_file(), so it works from a checkout, from an editable install and
    from a normal install.
    """
    aqui = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # source tree first: <repo>/version, two levels above src/sippts. It is
    # the one the author edits, so editing it has to take effect right away
    # without reinstalling, and the copy inside the package must not shadow it
    path = os.path.join(os.path.dirname(os.path.dirname(aqui)), "version")

    if os.path.isfile(path):
        return path

    # installed package: sippts/data/version.txt
    path = os.path.join(aqui, "data", "version.txt")

    if os.path.isfile(path):
        return path

    import sysconfig

    path = sysconfig.get_paths()["purelib"] + "/sippts/data/version.txt"

    if not os.path.isfile(path):
        path = path.replace("/usr/", "/usr/local/").replace(
            "/Library/Python", "/Library/Frameworks/Python.framework/Versions"
        )

    return path


def load_version():
    """
    Version of sippts, read from the version file so that releasing means
    editing one file and nothing else.
    """
    try:
        with open(version_file()) as f:
            valor = f.readline().strip()

        if valor != "":
            return valor
    except OSError:
        pass

    return _FALLBACK_VERSION


# kept as a name because params.py and sippts-gui import it
SIPPTS_VERSION = load_version()


# Names of the fields of self.found, in the same order in which each module
# joins them with ### when it builds a result line.
RESULT_FIELDS = {
    "scan": ("ip", "port", "proto", "response", "user_agent", "type", "fingerprint"),
    "scan_cve": ("device", "version", "cve", "type", "url"),
    "exten": ("ip", "port", "proto", "exten", "response", "user_agent"),
    "enumerate": ("method", "response", "user_agent", "fingerprint"),
    "leak": ("ip", "port", "proto", "response"),
    "rcrack": ("ip", "port", "proto", "user", "password"),
    "dcrack": ("ip_src", "ip_dst", "username", "password"),
    "astami": ("ip", "port", "status", "response", "version"),
}

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def result_rows(found, fields, sep="###"):
    """
    Turn the lines of self.found into a list of dictionaries.

    Extra fields are ignored and missing ones come out as "", so one badly
    formed line does not throw away the whole result. Colour codes and line
    breaks are stripped: the results are built from raw data, but some fields
    (the User-Agent of a device, for one) come from the other end.
    """
    rows = []

    for line in found:
        values = str(line).split(sep)
        row = dict()

        for i, name in enumerate(fields):
            value = values[i] if i < len(values) else ""
            value = _ANSI.sub("", str(value))
            row[name] = value.replace("\r", " ").replace("\n", " ").strip()

        rows.append(row)

    return rows


def write_results(found, fields, tool, jsonfile="", csvfile="", meta=None, sep="###"):
    """
    Write the results of a tool as JSON and/or CSV.

    found     the self.found list (lines joined with ###)
    fields    a tuple from RESULT_FIELDS
    tool      name of the command ("scan", "rcrack", ...)
    jsonfile  path of the JSON, "" not to write it
    csvfile   path of the CSV, "" not to write it
    meta      data about the run (target, port, proto, elapsed, ...)

    Never raises: a path that cannot be written is reported and the run goes
    on, the same way open_log() does.
    """
    if jsonfile == "" and csvfile == "":
        return

    rows = result_rows(found, fields, sep)

    if jsonfile != "":
        envelope = {
            "tool": tool,
            "version": load_version(),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": len(rows),
        }

        if meta:
            for key, value in meta.items():
                if value != None:
                    envelope[key] = value

        envelope["results"] = rows

        try:
            with open(jsonfile, "w") as f:
                json.dump(envelope, f, indent=2)
                f.write("\n")
        except OSError as error:
            print(f"{BRED}Error writing {jsonfile} ({error}){WHITE}")

    if csvfile != "":
        # "w" and not append: a CSV in append mode piles up header rows
        try:
            with open(csvfile, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(fields)

                for row in rows:
                    writer.writerow([row[name] for name in fields])
        except OSError as error:
            print(f"{BRED}Error writing {csvfile} ({error}){WHITE}")


def read_targets_file(path, default_port=5060, default_proto="UDP"):
    """
    Read a file of targets, one per line. Each line can be:

        ip:port/proto      192.168.0.10:5060/udp   (what scan -ot writes)
        ip:port            192.168.0.10:5060
        ip | host | net    192.168.0.0/24, 10.0.0.1-20, mypbx.com

    Empty lines and lines starting with # are skipped. Anything that is not
    ip:port/proto goes through expand_targets(), so this accepts both the
    network files of 'scan -f' and the target files of 'scan -ot'.

    Returns a list of (ip, port, proto) with no duplicates, and a list of the
    errors found, so the caller decides how to report them.
    """
    targets = []
    errors = []
    seen = set()

    try:
        f = open(path)
    except OSError as error:
        errors.append("Error reading file %s (%s)" % (path, error))
        return (targets, errors)

    with f:
        for line in f:
            line = line.strip()

            if line == "" or line.startswith("#"):
                continue

            port = default_port
            proto = default_proto
            host = line

            m = re.fullmatch(r"(.+?):(\d+)(?:/(\w+))?", line)
            if m:
                host = m.group(1)
                port = int(m.group(2))
                if m.group(3):
                    proto = m.group(3).upper()

            try:
                (ips, names) = expand_targets(host)
            except ValueError as error:
                errors.append(str(error))
                continue

            for ip in ips:
                key = (ip, port, proto)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)

    return (targets, errors)


def write_targets(path, found, sep="###"):
    """
    Write an ip:port/proto target file out of self.found, whose first three
    fields must be ip, port and proto. The result feeds 'leak -f', 'exten -f'
    and 'rcrack -f'.
    """
    lines = []
    seen = set()

    for line in found:
        values = str(line).split(sep)

        if len(values) < 3:
            continue

        entry = "%s:%s/%s" % (values[0], values[1], values[2])

        if entry not in seen:
            seen.add(entry)
            lines.append(entry)

    lines.sort(key=host_sort_key)

    try:
        with open(path, "w") as f:
            for entry in lines:
                f.write(entry + "\n")
    except OSError as error:
        print(f"{BRED}Error writing {path} ({error}){WHITE}")


def open_log(path, mode="a+"):
    """
    Open a log file reporting the problem instead of raising.

    A wrong path with -o used to abort with a traceback in the middle of
    printing the results, and everything found was lost.
    """
    try:
        return open(path, mode, buffering=1)
    except OSError as error:
        print(f"{RED}Error writing {path} ({error}){WHITE}")

        return _NullLog()


def packet_addresses(packet):
    """
    Return the (source, destination) addresses of a captured packet.

    A packet with no IPv4 or IPv6 layer gives (None, None) instead of raising
    AttributeError in the middle of reading a capture.
    """
    for layer in ("ip", "ipv6"):
        try:
            l = getattr(packet, layer)
            return (l.src, l.dst)
        except AttributeError:
            pass

    return (None, None)


def close_capture(capture):
    """
    Close a pyshark capture without leaving noise behind.

    When tshark crashes, close() raises and the running processes stay in the
    list, so pyshark's __del__ tries again at garbage collection time and the
    interpreter prints an 'Exception ignored while calling deallocator'
    traceback that has nothing to do with what the user was doing.
    """
    if capture is None:
        return

    try:
        capture.clear()
    except Exception:
        pass

    try:
        capture.close()
    except Exception:
        pass

    try:
        capture._running_processes.clear()
    except Exception:
        pass


def close_sockets(sock, sock_ssl=None):
    """
    Close a socket and its TLS wrapper.

    wrap_socket() takes over the file descriptor of `sock` (the plain socket is
    detached and its close() becomes a no-op), so closing only `sock` leaves
    the TLS connection open until the garbage collector gets to it.
    """
    for s in (sock_ssl, sock):
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def bind_local_port(sock, bind="0.0.0.0", lport=0):
    """
    Bind `sock` to a local port and return the bound port number.

    Tries `lport` when given, then a few free ports, and finally lets the
    kernel pick one. Returns 0 when every attempt failed, so the caller can
    close the socket instead of leaking it.
    """
    if lport:
        try:
            sock.bind((bind, int(lport)))
            return sock.getsockname()[1]
        except (OSError, ValueError):
            pass

    for _ in range(3):
        try:
            sock.bind((bind, get_free_port()))
            return sock.getsockname()[1]
        except OSError:
            pass

    try:
        sock.bind((bind, 0))
        return sock.getsockname()[1]
    except OSError:
        return 0


def generate_random_string(len_ini, len_end, type):
    len = generate_random_integer(len_ini, len_end)

    if type == "all":
        str = "".join(chr(i) for i in range(128))
        result_str = "".join(random.choice(str) for i in range(len))
    elif type == "printable_nl":
        result_str = "".join(
            random.choice(
                r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~\s\t\n\r\x0b\x0c'
            )
            for i in range(len)
        )
    elif type == "printable":
        result_str = "".join(
            random.choice(
                r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~\s'
            )
            for i in range(len)
        )
    elif type == "ascii":
        result_str = "".join(
            random.choice(r"0123456789abcdefghijklmnopqqrstuvwxyz") for i in range(len)
        )
    else:
        # By default use 'hex'
        result_str = "".join(random.choice("0123456789abcdef") for i in range(len))

    return result_str


def generate_random_integer(len_ini, len_end):
    return randint(len_ini, len_end)


# Default Accept for the events used in an audit. An unknown event goes out
# without Accept unless -accept says otherwise.
EVENT_ACCEPT = {
    "message-summary": "application/simple-message-summary",
    "presence": "application/pidf+xml",
    "presence.winfo": "application/watcherinfo+xml",
    "dialog": "application/dialog-info+xml",
    "refer": "message/sipfrag",
    "reg": "application/reginfo+xml",
    "conference": "application/conference-info+xml",
    "as-feature-event": "application/x-as-feature-event+xml",
}


def create_message(
    method,
    ip_sdp,
    contactdomain,
    fromuser,
    fromname,
    fromdomain,
    touser,
    toname,
    todomain,
    proto,
    domain,
    useragent,
    fromport,
    branch,
    callid,
    tag,
    cseq,
    totag,
    digest,
    auth_type,
    referto,
    withsdp,
    via,
    rr,
    ppi,
    pai,
    header,
    withcontact,
    *,
    event="",
    accept="",
    sub_expires="",
    ppi_domain="",
    pai_domain="",
):
    expires = "120"

    if method == "REGISTER" or method == "NOTIFY" or method == "ACK":
        starting_line = "%s sip:%s SIP/2.0" % (method, domain)
    else:
        starting_line = "%s sip:%s@%s SIP/2.0" % (method, touser, domain)

    if branch == "":
        branch = generate_random_string(71, 71, "ascii")
    if callid == "":
        callid = generate_random_string(32, 32, "hex")
    if tag == "":
        tag = generate_random_string(8, 8, "hex")

    if method == "REFER" and referto == "":
        referto = "999"

    headers = dict()
    if via == "":
        headers["Via"] = "SIP/2.0/%s %s:%s;branch=%s;rport" % (
            proto.upper(),
            contactdomain,
            fromport,
            branch,
        )
    else:
        headers["Via"] = via

    if rr != "":
        rrs = rr.split("#")
        count = 0

        # for rr in rrs:
        for rr in rrs[::-1]:
            count += 1
            headers["Route %s" % str(count)] = rr

    m = re.search(r"^from:\s*(.+)", header.lower())
    if not m:
        headers["From"] = "%s <sip:%s@%s>;tag=%s" % (
            fromname,
            fromuser,
            fromdomain,
            tag,
        )

    m = re.search(r"^to:\s*(.+)", header.lower())
    if not m:
        if method == "NOTIFY":
            if totag == "":
                headers["To"] = "<sip:%s>" % todomain
            else:
                headers["To"] = "<sip:%s>;tag=%s" % (todomain, totag)
        else:
            if totag == "":
                headers["To"] = "%s <sip:%s@%s>" % (toname, touser, todomain)
            else:
                headers["To"] = "%s <sip:%s@%s>;tag=%s" % (
                    toname,
                    touser,
                    todomain,
                    totag,
                )

    if withcontact == 1:
        m = re.search(r"^contact:\s*(.+)", header.lower())
        if not m:
            if method != "CANCEL" and method != "ACK":
                headers["Contact"] = "<sip:%s@%s:%d;transport=%s>;expires=%s" % (
                    fromuser,
                    contactdomain,
                    fromport,
                    proto,
                    expires,
                )

    headers["Call-ID"] = "%s" % callid

    if digest != "":
        if auth_type == 2:
            headers["Proxy-Authorization"] = "%s" % digest
        else:
            headers["Authorization"] = "%s" % digest

    headers["CSeq"] = "%s %s" % (cseq, method)
    headers["Max-Forwards"] = "70"

    if method == "REFER":
        headers["Refer-To"] = "<sip:%s@%s>" % (referto, domain)
        headers["Referred-By"] = "<sip:%s@%s:%s>" % (fromuser, domain, fromport)

    if method == "SUBSCRIBE":
        if event == "":
            # what it always did: an as-feature-event of Asterisk
            headers["Accept"] = "application/x-as-feature-event+xml"
            headers["Event"] = "as-feature-event"
        else:
            headers["Event"] = event

            if accept != "":
                headers["Accept"] = accept
            elif event.split(";")[0] in EVENT_ACCEPT:
                headers["Accept"] = EVENT_ACCEPT[event.split(";")[0]]

            # RFC 6665 asks for it, but only on the new path so that the
            # message of always does not change
            headers["Expires"] = sub_expires if sub_expires != "" else "3600"

    if method == "NOTIFY":
        if event == "":
            headers["Event"] = "keep-alive"
        else:
            headers["Event"] = event
            # mandatory in a NOTIFY according to RFC 6665, and never built
            headers["Subscription-State"] = "active;expires=%s" % (
                sub_expires if sub_expires != "" else "3600"
            )

    if method != "ACK":
        headers["User-Agent"] = "%s" % useragent
        if method != "CANCEL":
            headers["Allow"] = (
                "INVITE, REGISTER, ACK, CANCEL, BYE, NOTIFY, REFER, OPTIONS, INFO, SUBSCRIBE, UPDATE, PRACK, MESSAGE"
            )

    if method == "REGISTER":
        headers["Expires"] = "%s" % expires

    if withsdp == 1:
        headers["Content-Type"] = "application/sdp"
        headers["Accept"] = "application/sdp, application/dtmf-relay"

    if method == "INVITE":
        # the domain of these two was hardcoded to telefonica.net. It stays as
        # the default so nothing changes, but it can be set now, and a value
        # that already carries a @ is used as it is
        if ppi != "":
            if str(ppi).find("@") > 0:
                headers["P-Preferred-Identity"] = "<sip:%s>" % ppi
            else:
                headers["P-Preferred-Identity"] = "<sip:%s@%s>" % (
                    ppi,
                    ppi_domain if ppi_domain != "" else "telefonica.net",
                )

        if pai != "":
            if str(pai).find("@") > 0:
                headers["P-Asserted-Identity"] = "<sip:%s>" % pai
            else:
                headers["P-Asserted-Identity"] = "<sip:%s@%s>" % (
                    pai,
                    pai_domain if pai_domain != "" else "telefonica.net",
                )

    msg = starting_line + "\r\n"
    for h in headers.items():
        # msg += '%s: %s\r\n' % h
        name = h[0]
        value = h[1]

        m = re.search(r"^Route", name)
        if m:
            name = "Route"
        msg += "%s: %s\r\n" % (name, value)

    if header != "":
        h = header.split("&")

        for hdr in h:
            msg += "%s\r\n" % hdr

    sdp = ""
    if withsdp == 1:
        # Use RTP
        sdp = "\r\n"
        sdp += "v=0\r\n"
        sdp += "o=%s 8000 8000 IN IP4 %s\r\n" % (fromuser, ip_sdp)
        sdp += "s=SIPPTS\r\n"
        sdp += "c=IN IP4 %s\r\n" % ip_sdp
        sdp += "t=0 0\r\n"
        sdp += "m=audio 12194 RTP/AVP 0 9 8 18 3 110 101\r\n"
        sdp += "a=rtpmap:0 PCMU/8000\r\n"
        sdp += "a=rtpmap:9 G722/8000\r\n"
        sdp += "a=rtpmap:8 PCMA/8000\r\n"
        sdp += "a=rtpmap:18 G729/8000\r\n"
        sdp += "a=fmtp:18 annexb=no\r\n"
        sdp += "a=rtpmap:3 GSM/8000\r\n"
        sdp += "a=rtpmap:110 speex/8000\r\n"
        sdp += "a=rtpmap:101 telephone-event/8000\r\n"
        sdp += "a=fmtp:101 0-16\r\n"
        sdp += "a=ptime:20\r\n"
        sdp += "a=maxptime:60\r\n"
        sdp += "a=sendrecv\r\n"

    if withsdp == 2:
        # Use SRTP
        sdp = "\r\n"
        sdp += "v=0\r\n"
        sdp += "o=anonymous 1312841870 1312841870 IN IP4 %s\r\n" % ip_sdp
        sdp += "s=SIPPTS\r\n"
        sdp += "c=IN IP4 %s\r\n" % ip_sdp
        sdp += "t=0 0\r\n"
        sdp += "m=audio 12194 RTP/AVP 0 9 8 18 3 110 101\r\n"
        sdp += "a=rtpmap:0 PCMU/8000\r\n"
        sdp += "a=rtpmap:9 G722/8000\r\n"
        sdp += "a=rtpmap:8 PCMA/8000\r\n"
        sdp += "a=rtpmap:18 G729/8000\r\n"
        sdp += "a=fmtp:18 annexb=no\r\n"
        sdp += "a=rtpmap:3 GSM/8000\r\n"
        sdp += "a=rtpmap:110 speex/8000\r\n"
        sdp += "a=rtpmap:101 telephone-event/8000\r\n"
        sdp += "a=fmtp:101 0-16\r\n"
        sdp += "a=ptime:20\r\n"
        sdp += "a=maxptime:60\r\n"
        sdp += "a=sendrecv\r\n"
        sdp += "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:4EvYRd22P8n36wRrlWCMZIWegovyv7iWm464D4Pt\r\n"
        sdp += "a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:mWQ4cakWKOnfH9Tji2pEF87JtVFUqBAMPqub9roe\r\n"

    msg += "Content-Length: " + str(len(sdp)) + "\r\n"
    msg += sdp

    msg += "\r\n"

    return msg


def create_response_error(
    message,
    fromuser,
    touser,
    proto,
    domain,
    fromport,
    cseq,
    method,
    branch,
    callid,
    tag,
    totag,
    iplocal,
    via,
    auth_code,
    *,
    realm="asterisk",
    algorithm="MD5",
    nonce="",
):
    # keyword-only with the values of always as default: the challenge was
    # hardcoded to MD5 and realm="asterisk". Quite a few hardware phones only
    # answer when the realm matches the one of their provisioning, and a
    # server that only accepts SHA-256 could not be challenged at all
    if nonce == "":
        nonce = generate_random_string(8, 8, "ascii")

    digest = 'Digest algorithm=%s, realm="%s", nonce="%s"' % (algorithm, realm, nonce)

    starting_line = "SIP/2.0 %s" % message

    headers = dict()
    if via == "":
        headers["Via"] = "SIP/2.0/%s %s:%s;branch=%s;rport" % (
            proto.upper(),
            domain,
            fromport,
            branch,
        )
    else:
        vias = via.split("#")
        count = 0

        for via in vias[::-1]:
            count += 1
            headers["Via %s" % str(count)] = via

    headers["From"] = "<sip:%s@%s>;tag=%s" % (fromuser, domain, totag)
    headers["To"] = "<sip:%s@%s>;tag=%s" % (touser, iplocal, tag)
    headers["Call-ID"] = "%s" % callid
    headers["CSeq"] = "%d %s" % (cseq, method)
    if method == "BYE":
        headers[auth_code] = "%s" % digest
        # headers['WWW-Authenticate'] = '%s' % digest
        # headers['Proxy-Authenticate'] = '%s' % digest
    headers["Content-Length"] = "0"

    msg = starting_line + "\r\n"
    for h in headers.items():
        #     msg += '%s: %s\r\n' % h
        name = h[0]
        value = h[1]

        m = re.search(r"^Via", name)
        if m:
            name = "Via"
        msg += "%s: %s\r\n" % (name, value)

    msg += "\r\n"

    return msg


def create_response_ok(
    fromuser,
    touser,
    proto,
    domain,
    fromport,
    cseq,
    branch,
    callid,
    tag,
    totag,
    via="",
    fromhdr="",
    tohdr="",
):
    starting_line = "SIP/2.0 200 Ok"

    headers = dict()

    # a response has to copy the Via, From and To of the request (RFC 3261
    # 8.2.6.2): rebuilt from parts, the request had no matching transaction on
    # the other side and it kept retransmitting
    if via != "":
        count = 0

        for v in via.split("#")[::-1]:
            count += 1
            headers["Via %s" % str(count)] = v
    else:
        headers["Via"] = "SIP/2.0/%s %s:%s;branch=%s" % (
            proto.upper(),
            domain,
            fromport,
            branch,
        )

    if fromhdr != "":
        headers["From"] = fromhdr
    else:
        headers["From"] = "<sip:%s@%s>;tag=%s" % (fromuser, domain, totag)

    if tohdr != "":
        headers["To"] = tohdr
    else:
        headers["To"] = "<sip:%s@%s>;tag=%s" % (touser, domain, tag)

    headers["Call-ID"] = "%s" % callid
    headers["CSeq"] = "%d BYE" % cseq
    headers["Content-Length"] = "0"

    msg = starting_line + "\r\n"

    for h in headers.items():
        name = h[0]
        value = h[1]

        m = re.search(r"^Via", name)
        if m:
            name = "Via"

        msg += "%s: %s\r\n" % (name, value)

    msg += "\r\n"

    return msg


def parse_message(buffer):
    headers = buffer.split("\r\n")

    data = dict()
    data["response_text"] = ""
    data["response_code"] = ""
    data["sipuser"] = ""
    data["sipdomain"] = ""
    data["ua"] = ""
    data["via"] = ""
    data["via2"] = ""
    data["rr"] = ""
    data["route"] = ""
    data["auth-type"] = 1
    data["type"] = "Unknown"
    # every key always exists: these were created only when the header was
    # present, so reading them raised KeyError on any other message and the
    # callers silently discarded the whole packet
    data["method"] = ""
    data["sipport"] = ""
    data["fromuser"] = ""
    data["fromtag"] = ""
    data["branch"] = ""
    data["callid"] = ""
    data["cseq"] = ""
    data["from"] = ""
    data["to"] = ""
    data["totag"] = ""
    data["contactuser"] = ""
    data["contactdomain"] = ""
    data["auth"] = ""

    for header in headers:
        m = re.search(r"^SIP\/[0-9|\.]+\s([0-9]+)\s(.+)", header)
        if m:
            data["response_code"] = "%s" % (m.group(1))
            data["response_text"] = "%s" % (m.group(2))

        m = re.search(r"([a-z|A-Z]+)\ssip\:(.*)\sSIP\/[0-9|\.]*", header)
        if m:
            data["method"] = "%s" % (m.group(1))
            uri = "%s" % (m.group(2))
            if uri.find("@") > 0:
                n = re.search(r"(.*)@(.*)", uri)
                data["sipuser"] = "%s" % (n.group(1))
                data["sipdomain"] = "%s" % (n.group(2))
            else:
                data["sipdomain"] = uri
            if data["sipdomain"].find(":") > 0:
                n = re.search(r"(.*):(.*)", uri)
                data["sipdomain"] = "%s" % (n.group(1))
                data["sipport"] = "%s" % (n.group(2))
            else:
                data["sipport"] = "5060"

        m = re.search(r"^From:\s*.*\<sip:([a-z|A-z|0-9|_]*)\@.*", header)
        if m:
            data["fromuser"] = "%s" % (m.group(1))

        m = re.search(r"^From:\s*(.+)", header)
        if m:
            hfrom = "%s" % (m.group(1))
            data["from"] = hfrom

            try:
                n = re.search(r".*;tag=(.+)", hfrom)
                if n:
                    data["fromtag"] = "%s" % (n.group(1))
                else:
                    data["fromtag"] = ""
            except:
                data["fromtag"] = ""

        m = re.search(r"^Record-Route:\s*(.*)", header)
        if m:
            if data["rr"] == "":
                data["rr"] = "%s" % (m.group(1))
            else:
                data["rr"] = data["rr"] + "#" + "%s" % (m.group(1))

        m = re.search(r"^Via:\s*(.*)", header)
        if m:
            data["via"] = "%s" % (m.group(1))

            if data["via2"] == "":
                data["via2"] = "%s" % (m.group(1))
            else:
                data["via2"] = "%s" % (m.group(1)) + "#" + data["via2"]

            n = re.search(r".+;branch=(.+);*.*", data["via"])
            if n:
                data["branch"] = "%s" % (n.group(1))
            else:
                data["branch"] = ""

        m = re.search(r"^Call-ID:\s*(.*)", header)
        if m:
            data["callid"] = "%s" % (m.group(1))

        m = re.search(r"^Server:\s*(.+)", header)
        if m:
            data["ua"] = "%s" % (m.group(1))
            data["type"] = "Server"
        else:
            m = re.search(r"^User-Agent:\s*(.+)", header)
            if m:
                data["ua"] = "%s" % (m.group(1))
                data["type"] = "Device"

        m = re.search(r"^To:\s*(.+)", header)
        if m:
            to = "%s" % (m.group(1))
            data["to"] = to

            try:
                n = re.search(r".*;tag=(.+)", to)
                if n:
                    data["totag"] = "%s" % (n.group(1))
                else:
                    data["totag"] = ""
            except:
                data["totag"] = ""

        m = re.search(r"^Contact:\s*(.+)", header)
        if m:
            m = re.search(r"\@", header)
            if m:
                m = re.search(
                    r"^Contact:\s*.*\<sip:([a-z|A-z|0-9|_]*)\@(.*)\>.*", header
                )
                # r'^Contact:\s*.*\<sip:([a-z|A-z|0-9|_]*)\@([0-9|\.]*):*.*\>.*', header)
                if m:
                    data["contactuser"] = "%s" % (m.group(1))
                    data["contactdomain"] = "%s" % (m.group(2))
            else:
                m = re.search(r"^Contact:\s*.*\<sip:(.*)\>.*", header)
                if m:
                    data["contactuser"] = ""
                    data["contactdomain"] = "%s" % (m.group(1))

        m = re.search(r"^CSeq:\s*([0-9]+)\s.*", header)
        if m:
            data["cseq"] = "%s" % (m.group(1))

        m = re.search(r"^Authorization:\s*(.+)", header)
        if m:
            data["auth"] = "%s" % (m.group(1))
        else:
            # the answer to a 407 challenge: it was not recognized, so the
            # digest of a victim that honours a 407 was never captured
            m = re.search(r"^Proxy-Authorization:\s*(.+)", header)
            if m:
                data["auth"] = "%s" % (m.group(1))
                data["auth-type"] = 2
            else:
                m = re.search(r"^WWW-Authenticate:\s*(.+)", header)
                if m:
                    data["auth"] = "%s" % (m.group(1))
                    data["auth-type"] = 1
                else:
                    m = re.search(r"^Proxy-Authenticate:\s*(.+)", header)
                    if m:
                        data["auth"] = "%s" % (m.group(1))
                        data["auth-type"] = 2

        m = re.search(r"^CSeq:\s*([0-9]+)\s.*", header)
        if m:
            data["cseq"] = "%s" % (m.group(1))

    return data


def _sha512_256(data=b""):
    """
    SHA-512/256 of FIPS 180-4, the algorithm RFC 8760 defines for SIP.

    It is NOT SHA-512 cut down to 64 hex characters: it uses a different
    initialization vector, so truncating gives a completely different value
    and the server rejects the credentials.
    """
    return hashlib.new("sha512_256", data)


try:
    _sha512_256(b"")
    _HAS_SHA512_256 = True
except ValueError:
    # the OpenSSL of the system does not provide it
    _HAS_SHA512_256 = False


# RFC 8760 defines SHA-256 and SHA-512-256 for SIP. SHA-1 and plain SHA-512
# are not in the RFC but are kept because they were already accepted here.
_HASH_ALGORITHMS = {
    "MD5": hashlib.md5,
    "SHA": hashlib.sha1,
    "SHA1": hashlib.sha1,
    "SHA-1": hashlib.sha1,
    "SHA-256": hashlib.sha256,
    "SHA256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
    "SHA512": hashlib.sha512,
}

if _HAS_SHA512_256:
    _HASH_ALGORITHMS["SHA-512-256"] = _sha512_256
    _HASH_ALGORITHMS["SHA512-256"] = _sha512_256
    _HASH_ALGORITHMS["SHA-512/256"] = _sha512_256

# algorithms already reported as unknown, to warn only once each
_warned_algorithms = set()


def normalize_algorithm(algorithm):
    """
    Upper case and without the -sess suffix, which only changes how HA1 is
    built and not which hash function is used.
    """
    return re.sub(r"-?SESS$", "", str(algorithm).strip().upper())


def supported_algorithms():
    """Names of the digest algorithms this build can really compute."""
    return sorted(set(_HASH_ALGORITHMS))


def algorithm_supported(algorithm):
    return normalize_algorithm(algorithm) in _HASH_ALGORITHMS


# RFC 8760 asks the client to answer the strongest challenge it supports.
# A -sess variant counts as its base algorithm.
_ALGORITHM_STRENGTH = ["SHA-512-256", "SHA-256", "SHA-1", "MD5"]


def parse_digest_challenge(header):
    """
    Read ONE authentication header and return its fields.

    Returns None if the line carries no digest data at all.
    """
    data = dict()

    # the defaults are set once: inside the loop every line reset the fields
    # matched by the previous one
    data["username"] = ""
    data["realm"] = ""
    data["nonce"] = ""
    data["uri"] = ""
    data["response"] = ""
    data["algorithm"] = "MD5"
    data["cnonce"] = ""
    data["nc"] = ""
    data["qop"] = ""

    # a quoted value is read up to its closing quote: the hand made character
    # classes dropped a username with + or @ (an E.164 number), a realm with a
    # space and a response in upper case hex, leaving the field empty
    quoted = {
        "username": r"username=\"([^\"]*)\"",
        "realm": r"realm=\"([^\"]*)\"",
        "nonce": r"(?<!c)nonce=\"([^\"]*)\"",
        "uri": r"uri=\"([^\"]*)\"",
        "response": r"response=\"([^\"]*)\"",
        "cnonce": r"cnonce=\"([^\"]*)\"",
    }

    visto = False

    for field, regex in quoted.items():
        m = re.search(regex, header)
        if m:
            data[field] = "%s" % (m.group(1))
            visto = True

    # these three travel quoted or bare depending on the implementation
    m = re.search(r"algorithm=\"*([\w\-]+)\"*", header)
    if m:
        data["algorithm"] = "%s" % (m.group(1))
        visto = True

    m = re.search(r"\bnc=\"*([\w\+]+)\"*", header)
    if m:
        data["nc"] = "%s" % (m.group(1))
        visto = True

    m = re.search(r"\bqop=\"*([\w\+]+)\"*", header)
    if m:
        data["qop"] = "%s" % (m.group(1))
        visto = True

    if visto == False:
        return None

    return data


def parse_digest_challenges(buffer):
    """
    All the authentication challenges of a message, one per header.

    A server that offers several algorithms sends one WWW-Authenticate per
    algorithm, each with its OWN nonce.
    """
    challenges = []

    for header in buffer.split("\r\n"):
        data = parse_digest_challenge(header)

        if data != None:
            challenges.append(data)

    return challenges


def select_challenge(challenges, preferred=""):
    """
    Pick the challenge to answer: the strongest one we can really compute,
    or the one whose algorithm matches `preferred`.
    """
    if challenges == []:
        return None

    if preferred != "":
        want = normalize_algorithm(preferred)

        for data in challenges:
            if normalize_algorithm(data["algorithm"]) == want:
                return data

        return None

    mejor = None
    posicion = len(_ALGORITHM_STRENGTH)

    for data in challenges:
        alg = normalize_algorithm(data["algorithm"])

        if algorithm_supported(alg) == False:
            continue

        try:
            pos = _ALGORITHM_STRENGTH.index(alg)
        except ValueError:
            # supported but not ranked (plain SHA-512): below the ranked ones
            pos = len(_ALGORITHM_STRENGTH)

        if mejor == None or pos < posicion:
            mejor = data
            posicion = pos

    if mejor == None:
        # none of them can be computed: answer the first one and let getHash
        # report the unknown algorithm
        return challenges[0]

    return mejor


def parse_digest(buffer, preferred=""):
    """
    Fields of the digest of a message.

    This used to walk every line accumulating into a SINGLE dict, so a server
    offering two algorithms (one WWW-Authenticate each, with different nonces)
    ended up mixing fields of different challenges: the nonce of one and the
    realm of another, and the response went out impossible to verify.
    """
    challenges = parse_digest_challenges(buffer)

    data = select_challenge(challenges, preferred)

    if data != None:
        return data

    # nothing recognizable: same empty structure as always, so the callers
    # that only read fields keep working
    return parse_digest_challenge("") or {
        "username": "",
        "realm": "",
        "nonce": "",
        "uri": "",
        "response": "",
        "algorithm": "MD5",
        "cnonce": "",
        "nc": "",
        "qop": "",
    }


def getHash(algorithm, string):
    # the algorithm can arrive in any case, empty, or with the -sess suffix
    # (MD5-sess, SHA-256-sess): the hash function is the same one
    alg = normalize_algorithm(algorithm)

    hashfunc = _HASH_ALGORITHMS.get(alg)

    if hashfunc is None:
        # MD5 is the default of RFC 2617 when the server sends no algorithm.
        # With an algorithm that IS there but we cannot compute, the hash goes
        # out wrong and the server just answers 401 again: say so instead of
        # reporting wrong credentials. To stderr, so it does not get in the
        # way of anything parsing the output
        if alg != "" and alg not in _warned_algorithms:
            _warned_algorithms.add(alg)
            print(
                f"[!] Unknown digest algorithm '{algorithm}', falling back to "
                f"MD5: the response will be wrong. Supported: "
                f"{', '.join(supported_algorithms())}",
                file=sys.stderr,
            )

        hashfunc = hashlib.md5

    return hashfunc(string.encode()).hexdigest()


def calculateHash(
    username,
    realm,
    pwd,
    method,
    uri,
    nonce,
    algorithm,
    cnonce,
    nc,
    qop,
    verbose,
    entitybody,
):
    # HA1 = MD5(username:realm:password)
    # HA2 = MD5(method:digestURI)
    # response = MD5(HA1:nonce:HA2)

    # If the algorithm directive's value is "MD5-sess":
    #   HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
    # If the qop directive's value is "auth-int":
    #   HA2 = MD5(method:digestURI:MD5(entityBody))
    # If the qop directive's value is "auth" or "auth-int":
    #   response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)

    a1 = "%s:%s:%s" % (username, realm, pwd)
    a2 = "%s:%s" % (method, uri)

    ha1 = getHash(algorithm, a1)
    # any -sess variant, not only MD5-sess: SHA-256-sess and SHA-512-256-sess
    # were building HA1 the wrong way
    if str(algorithm).strip().upper().endswith("-SESS"):
        a1 = "%s:%s:%s" % (ha1, nonce, cnonce)
        ha1 = getHash(algorithm, a1)
    ha2 = getHash(algorithm, a2)
    if (qop == "auth" or qop == "auth-int") and cnonce != "":
        # auth-int hashes the body ALSO when it is empty, H(""): deciding by
        # the body instead of by the qop left auth-int wrong even with no body
        if qop == "auth-int":
            a2 = "%s:%s:%s" % (method, uri, getHash(algorithm, entitybody))
            ha2 = getHash(algorithm, a2)
        b = "%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2)
    else:
        b = "%s:%s:%s" % (ha1, nonce, ha2)
    ret = getHash(algorithm, b)

    if verbose == 1:
        print(f"{WHITE}Calculating {algorithm} hash:")
        print(f"{WHITE}A1 hash {algorithm}({a1}): {ha1}")
        print(f"{WHITE}A2 hash {algorithm}({a2}): {ha2}")
        print(f"{WHITE}B  hash {algorithm}({b}): {ret}")
        print(WHITE)
    return ret


def format_time(value):
    if value < 60:
        return str(value) + " sec(s)"

    m = int(value / 60)
    s = value % 60

    if m < 60:
        return str(m) + " min(s) " + str(s) + " sec(s)"

    h = int(m / 60)
    m = m % 60

    return str(h) + " hour(s) " + str(m) + " min(s) " + str(s) + " sec(s)"


def fingerprinting(method, msg, headers, verbose):
    fp = []

    tag = headers["totag"]
    ua = headers["ua"]
    type = headers["type"]
    code = headers["response_code"]

    if method == "REGISTER":
        if code == "405":
            type = "Device"
        if code == "401":
            type = "Server"

    # Device or Unknown
    if type != "Server":
        m = re.search(r"^[a-fA-F0-9]{6,8}-[a-fA-F0-9]{2,4}$", tag)
        if m:
            fp.append("Cisco VoIP Gateway")
        m = re.search(r"^[a-fA-F0-9]{16}i0$", tag)
        if m:
            fp.append("Sipura/Linksys SPA")
        m = re.search(r"^[0-9]{5,10}$", tag)
        if m:
            fp.append("Grandstream")
            fp.append("Aastra")
            fp.append("Dahua")
        m = re.search(r"^[0-9]{8,10}$", tag)
        if m:
            fp.append("Fanvil")
            fp.append("eXosip")
            fp.append("Linphone")
            fp.append("Kedacom")
        m = re.search(r"^[a-f0-9]{8}$", tag)
        if m:
            if ua[0:2] == "Z ":
                fp.clear()
                fp.append("Zoiper")
            else:
                fp.append("Cisco IP Phone")
                fp.append("3CX Phone")
                fp.append("Mitel Border GW")
                fp.append("Abto SIP SDK")
                fp.append("ReadyNet")
                fp.append("Tesira")
        m = re.search(r"^[a-z0-9]{10}$", tag)
        if m and tag[0:2] != "as":
            # Panasonic was added twice, so it showed up duplicated
            fp.append("Panasonic")
            fp.append("RM")
            fp.append("Grandstream")
            fp.append("IceWarp")
        m = re.search(r"^[a-z]{8}$", tag)
        if m:
            fp.append("Ozeki VoIP SIP SDK")
        m = re.search(r"^[0-9]{8,10}$", tag)
        if m:
            if ua[0:6] == "Estech":
                fp.clear()
                fp.append("ESI")
            else:
                fp.append("Draytek")
                fp.append("Yealink")
                fp.append("Cellgate")
                fp.append("Akuvox")
        m = re.search(r"^[a-f0-9]{16}$", tag)
        if m:
            fp.append("Grandstream")
        m = re.search(r"^plcm_", tag)
        if m:
            fp.append("Polycom")
        m = re.search(r"^[a-f0-9]{15}$", tag)
        if m:
            fp.append("Sangoma")
            fp.append("Tandberg")
        m = re.search(r"^[a-f0-9]{32}$", tag)
        if m:
            fp.append("Comrex")
            fp.append("OXO")
            fp.append("InterVideo")
            fp.append("Dahua")
        m = re.search(r"^[0-9a-f]{2}-[0-9]{8,10}$", tag)
        if m:
            fp.append("Sercomm Router")
        m = re.search(
            "^[0-9a-f]{6,8}-[0-9a-f]{6,8}-[0-9a-f]{4}-[0-9a-f]{5}-[0-9a-f]{1}-[0-9a-f]{5,8}-[0-9a-f]{6,8}-[0-9a-f]{5,8}$",
            tag,
        )
        if m:
            fp.append("Matrix")
        m = re.search(
            "^[0-9a-f]{7,8}-[0-9a-f]{7,8}-[0-9a-f]{5,6}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}$",
            tag,
        )
        if m:
            fp.append("Matrix")
        m = re.search(
            "^[0-9a-f]{6,8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{7,8}-[0-9a-f]{8}$",
            tag,
        )
        if m:
            if ua[0:8] == "Inventel":
                fp.append("Livebox")
            else:
                fp.append("Matrix")
                fp.append("Livebox")
        m = re.search(
            "^[0-9a-f]{6,8}-[0-9a-f]{10,15}-[0-9a-f]{7,8}-[0-9a-f]{7,8}-[0-9a-f]{7}$",
            tag,
        )
        if m:
            fp.append("Matrix")
        m = re.search(
            "^[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{5}-[0-9a-f]{5}-[0-9a-f]{8}-[0-9a-f]{5}$",
            tag,
        )
        if m:
            fp.append("Sagem")
        m = re.search(
            "^[0-9a-f]{6,7}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{5}-[0-9a-f]{5,6}-[0-9a-f]{7,8}-[0-9a-f]{5,6}$",
            tag,
        )
        if m:
            if ua[0:11] == "MediaAccess":
                fp.append("Technicolor")
            else:
                fp.append("Thomson")
                fp.append("Technicolor")
        m = re.search(r"^[0-9A-F]{16}$", tag)
        if m:
            fp.append("Fritz")
        m = re.search(r"^ZyXELUA_[0-9]{10}-[0-9]{4}$", tag)
        if m:
            fp.append("ZyXEL")
        m = re.search(r"^[0-9a-z]{71}$", tag)
        if m:
            if ua[0:7] == "Maxwell":
                fp.append("Gigaset")
            elif ua[0:4] == "TSW-":
                fp.append("Creston")
            else:
                fp.append("Yealink")
                fp.append("TP-Link")
                fp.append("Gigaset")
                fp.append("DoorBird")
                fp.append("Axis")
                fp.append("Digium")
        m = re.search(r"^as[0-9a-f]{8}$", tag)
        if m:
            if ua[0:4] == "FPBX" or ua[0:4] == "IPBX":
                fp.append("Asterisk PBX")
            else:
                fp.append("Asterisk PBX")
                fp.append("Huawei")
                fp.append("BeWAN")
                fp.append("XiVO")
        m = re.search(
            "^[a-f0-9]{6}-[a-f0-9]{7,8}-[a-f0-9]{4}-[a-f0-9]{5}-[a-f0-9]{7,8}-[a-f0-9]{7,8}-[a-f0-9]{7,8}$",
            tag,
        )
        if m:
            fp.append("Skype for Business")
        m = re.search(r"^ZyXELUA_", tag)
        if m:
            fp.append("ZyXEL")
        m = re.search(r"^[0-9]{8,10}$", tag)
        if m:
            if ua[0:4] == "ININ":
                fp.clear()
                fp.append("Interactive Intelligence EDGE")
        m = re.search(r"^0\.0\.0\.0\+1\+[0-9a-z]{7,8}\+[0-9a-z]{7,8}$", tag)
        if m:
            fp.append("Calix")
        m = re.search(
            "^[0-9a-f]{7}-[0-9]{1}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{6}-[0-9a-f]{8}-[0-9a-f]{6}$",
            tag,
        )
        if m:
            fp.append("ShoreGear")

        if tag == "123456":
            fp.append("Alcatel")

        if tag == "":
            m = re.search(r"^[A-Z]{1,2}[0-9]{2,3}\sIP", ua)
            if m:
                fp.append("Gigaset")
            elif headers["to"][0:1] != "<":
                fp.append("Intelbras")
            else:
                fp.append("SNOM")
                fp.append("FortiVoice")
                fp.append("AddPac")
                fp.append("Gigaset")
                fp.append("VTechET")
                fp.append("STL-IP")
                fp.append("Laia")
                fp.append("REDCOM")

        hdr = msg.split("\r\n")
        for h in hdr:
            if h.lower().find('realm="3cxphonesystem"') > 0:
                fp.clear()
                fp.append("3CX Phone System")
            if h.lower().find("x-grandstream-pbx:") == 0:
                fp.append("Grandstream ")

    # Server or Unknown or not found in Device
    if type != "Device" or fp == []:
        m = re.search(r"^as[0-9a-f]{8}$", tag)
        if m:
            if ua[0:2] == "TE":
                fp.append("Yeastar")
            elif (
                ua[0:4] == "FPBX"
                or ua[0:4] == "IPBX"
                or ua[0:3] == "MOR"
                or ua[0:8] == "Asterisk"
            ):
                fp.append("Asterisk PBX")
            elif ua[0:2] == "UC":
                fp.append("Openvox")
            elif ua[0:5] == "Aline":
                fp.append("Aline")
            elif ua[0:5] == "Cisco":
                fp.append("Cisco/SPA")
            elif ua[0:10] == "FortiVoice":
                fp.append("FortiVoice")
            elif ua[0:8] == "VoxStack":
                fp.append("VoxStack")
            elif ua[0:3] == "BEC":
                fp.append("BEC")
            else:
                fp.append("Asterisk PBX")
        m = re.search(r"^[0-9a-z]{71}$", tag)
        if m:
            if ua[0:4] == "FPBX" or ua[0:4] == "IPBX":
                fp.append("Asterisk PBX")
            elif ua[0:10] == "FortiVoice":
                fp.append("FortiVoice")
            else:
                fp.append("Asterisk PBX")
                fp.append("Yeastar")
                fp.append("Grandstream")
                fp.append("TP-Link")
                fp.append("SylkServer")
                fp.append("ESI")
                fp.append("ClearlyIP")
        m = re.search(r"^[a-z0-9A-Z]{11}.[a-z0-9A-Z]{32}.[0-9]{1}$", tag)
        if m:
            fp.append("Asterisk PBX")
        m = re.search(r"^[a-f0-9]{32}.[a-f0-9]{2,8}$", tag)
        if m:
            if ua[0:8] == "OpenSIPS":
                fp.append("OpenSIPS SIP Proxy")
            elif ua[0:6] == "Siedle":
                fp.append("Siedle")
            else:
                fp.append("Kamailio SIP Proxy")
        m = re.search(r"^DL[a-f0-9]{10}$", tag)
        if m:
            fp.append("LifeSize Media Server")
        m = re.search(r"^[a-zA-Z0-9]{13}$", tag)
        if m:
            fp.append("FreeSWITCH")
        m = re.search(r"^[0-9a-z]{4}[\.-][0-9a-z]{32}$", tag)
        if m:
            fp.append("OpenSIPS SIP Proxy")
        m = re.search(r"^[0-9A-F]{8}-[0-9A-F]{16}-[0-9A-F]{8}$", tag)
        if m:
            fp.append("SEMS")
        m = re.search(r"^[0-9]{10}$", tag)
        if m and ua[0:4] == "Desk" and ua[5:10] == "Phone":
            fp.clear()
            fp.append("OpenScape")
        m = re.search(r"^[0-9A-F]{3,4}$", tag)
        if m:
            fp.append("OneAccess")
        m = re.search(r"^[0-9A-F]{1}-[0-9A-F]{8}-[0-9A-F]{16}-[0-9A-F]{8}$", tag)
        if m:
            fp.append("Yeti")
        m = re.search(r"^[0-9a-z]{10}$", tag)
        if m:
            fp.append("Brekeke")
            fp.append("MediaCore")
            fp.append("XiVO")

        if fp == []:
            m = re.search(r"^[a-fA-F0-9]{6,8}-[a-fA-F0-9]{1,4}$", tag)
            if m:
                fp.append("Cisco SIP Gateway")
            m = re.search(
                "^[a-f0-9]{18}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", tag
            )
            if m:
                fp.append("Epygi Quadro")
            m = re.search(r"^[a-f0-9]{16}$", tag)
            if m:
                fp.append("Tandberg")
                fp.append("Algo")
            m = re.search(r"^[0-9a-f]{19,20}$", tag)
            if m:
                fp.append("Ingate")
                fp.append("SIParator")
                fp.append("StarkPBX")
            m = re.search(r"^[0-9]{5,10}$", tag)
            if m:
                fp.append("Panasonic")
            m = re.search(r"^[0-9]{8,10}$", tag)
            if m:
                fp.append("Yate")
                fp.append("Mediatrix")
                fp.append("MediaCore")
            m = re.search(r"^[0-9]{10}$", tag)
            if m:
                fp.append("M5T")
            m = re.search(r"^[0-9a-f]{16}-[0-9a-f]{8}$", tag)
            if m:
                fp.append("ZTE")
            m = re.search(r"^[0-9A-Z]{32}$", tag)
            if m:
                fp.append("RTC")
            m = re.search(r"^[0-9a-f]{32}$", tag)
            if m:
                fp.append("PhonerLite")
            m = re.search(r"^[0-9a-z]{16}$", tag)
            if m:
                fp.append("Cisco")
            m = re.search(r"^[0-9a-z]{17,18}$", tag)
            if m:
                fp.append("Cisco/SPA")
            m = re.search(r"^1c[0-9]{9,10}$", tag)
            if m:
                fp.append("Mediant SBC")
            m = re.search(r"^[0-9]{5,10}$", tag)
            if m:
                fp.append("OpenScape")
                fp.append("Aastra")
                fp.append("SNOM")
            m = re.search(r"^[0-9A-F]{8}$", tag)
            if m:
                fp.append("CommuniGate")
            m = re.search(r"^[0-9A-F]{24}$", tag)
            if m:
                fp.append("NEC")
            m = re.search(r"^[0-9A-Z]{18}$", tag)
            if m:
                fp.append("Aastra")
            m = re.search(r"^[a-f0-9]{7}-[a-f0-9]{6}$", tag)
            if m and ua[0:5] == "SONUS":
                fp.append("Skype for Business")

        if tag == "12345678":
            fp.append("Alcatel")
        if tag == "":
            if ua[0:5] == "Acano":
                fp.append("Cisco Meeting Server")
            else:
                fp.append("Aastra SIP Server")
                fp.append("Yate SIP Server")
                fp.append("Epygi Quadro")

        hdr = msg.split("\r\n")
        for h in hdr:
            if h.lower().find("av-global-session-id:") == 0:
                fp.append("Avaya Session Manager")
            if (
                h.lower().find("www-authenticate:") == 0
                and h.lower().find('realm="asterisk"') > 0
            ):
                fp.clear()
                fp.append("Asterisk PBX")
            if h.lower().find("o=ciscosystemssip-gw-useragent") == 0:
                fp.append("Cisco SIP Gateway")
    if ua != "":
        for f in fp:
            if (
                ua.lower()
                .replace(" ", "")
                .replace("-", "")
                .find(f.lower().replace(" ", "").replace("-", ""))
                == 0
            ):
                return [f]

    if fp == []:
        return ["Unknown"]

    if len(fp) > 3 and verbose != 2:
        return ["Too many matches"]

    clearfp = []

    for f in fp:
        if f not in clearfp:
            clearfp.append(f)

    return clearfp


def cve_file():
    """
    Path of the bundled CVE list.

    Resolved from the package itself, so it works on a normal install, on an
    editable install (where site-packages holds no sippts directory) and when
    running from a checkout. The install paths are kept as a fallback.
    """
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cve.csv"
    )

    if os.path.isfile(path):
        return path

    import sysconfig

    path = sysconfig.get_paths()["purelib"] + "/sippts/data/cve.csv"

    if not os.path.isfile(path):
        path = path.replace("/usr/", "/usr/local/").replace(
            "site-packages", "dist-packages"
        )

    return path


def load_cve_version():
    path = cve_file()

    if not os.path.isfile(path):
        return "Unknown"

    try:
        with open(path) as f:
            line = f.readline().strip("\n")

        f.close()

        aux = line.split(";")

        return aux[1]
    except:
        return "Unknown"

def load_cve():
    path = cve_file()

    if not os.path.isfile(path):
        return []

    cve = []

    f = open(path, "r")
    c = 0

    for line in f:
        if c > 0:
            line = line.replace("\n", "")
            line = line.replace(";", "###")
            if len(line) > 0:
                cve.append(line)
        c += 1

    f.close()

    return cve


def check_model(ua, fp, type, cvelist):
    found = []
    model = "$$$"
    version = "$$$"
    firmware = "$$$"

    aux = ua.lower().split(" ")
    l = len(aux)

    model = aux[0]

    # an empty needle makes find() match every line of the list
    if model == "" and fp == "":
        return found

    # if model == 'grandstream':
    if l > 1:
        version = aux[1]
    if l > 2:
        firmware = aux[2]

    for cve in cvelist:
        cve = cve.lower()
        if cve.find(model) > -1 and cve.find(version) > -1 and cve.find(firmware) > -1:
            found.append(cve)

    if len(found) == 0:
        for cve in cvelist:
            cve = cve.lower()
            if cve.find(model) > -1:
                if (
                    cve.find(version) > -1
                    or cve.replace(" ", "").find(version) > -1
                    or cve.find(version.replace(" ", "")) > -1
                    or cve.replace(" ", "").find(version.replace(" ", "")) > -1
                ):
                    found.append(cve)
                elif (
                    cve.replace("-", "").find(version) > -1
                    or cve.find(version.replace("-", "")) > -1
                    or cve.replace("-", "").find(version.replace("-", "")) > -1
                ):
                    found.append(cve)

    if len(found) == 0 and type == "Server":
        aux = fp.lower().split(" ")
        model = aux[0]

        # without a fingerprint there is nothing to look for: searching for an
        # empty string returned the whole CVE list as a match
        if model != "":
            for cve in cvelist:
                cve = cve.lower()
                if cve.find(model) > -1:
                    found.append(cve)

    return found
