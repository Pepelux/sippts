#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.2"
__license__ = "GPL"
__copyright__ = "Copyright 2015-2026, SIPPTS"
__email__ = "pepeluxx@gmail.com"

"""Reads what a TLS peer presents and turns it into findings.

sippts connects with CERT_NONE on purpose: it audits a server instead of
trusting it, so a self signed or expired certificate has to be looked at, not
refused. That is also why getpeercert() comes back empty and the DER has to be
read by hand, in lib/tlsx509.py.

The chain is NOT validated here. Rebuilding path validation is the kind of
code that goes wrong quietly, so OpenSSL is asked instead, with one extra
connection, and its verdict is reported as it words it. Expiry, self signature
and hostname are also worked out locally, so that they still answer on a
machine with no CA store at all.
"""

import re
import socket
import ssl
from datetime import datetime, timezone

from .tlsx509 import parse_der, campo, texto_nombre


# what OpenSSL will not even offer, so it can never be tested from here
_VERSIONES = (
    ("TLSv1.0", "TLSv1", "HAS_TLSv1"),
    ("TLSv1.1", "TLSv1_1", "HAS_TLSv1_1"),
    ("TLSv1.2", "TLSv1_2", "HAS_TLSv1_2"),
    ("TLSv1.3", "TLSv1_3", "HAS_TLSv1_3"),
)

# a default certificate of a VoIP box: its private key ships inside the
# firmware image, so anyone who downloads it can sit in the middle of the
# SIP-TLS. Only names no real deployment would put in a certificate it paid
# for: generic words like voip, sbc or example.com are deliberately NOT here,
# they show up in legitimate names and this finding is HIGH
_VENDOR_DEFECTO = (
    "localhost",
    "asterisk",
    "kamailio",
    "opensips",
    "freeswitch",
    "freepbx",
    "sangoma",
    "acmepacket",
    "grandstream",
    "yealink",
    "snom",
    "polycom",
    "audiocodes",
    "avaya",
    "mitel",
    "3cx",
    "changeme",
    "selfsigned",
    "sipcommunicationsservice",
)

_CIPHER_ALTO = ("NULL", "EXPORT", "anon", "ADH", "AECDH", "RC2")
_CIPHER_MEDIO = ("RC4", "DES-CBC3", "3DES", "DES", "IDEA", "SEED", "MD5")

_FIRMA_ALTA = ("md5", "md2")
_FIRMA_MEDIA = ("sha1",)


def _ahora():
    return datetime.now(timezone.utc)


def _fecha(texto):
    """The 'Jun  1 12:00:00 2026 GMT' of getpeercert() -> datetime, or None."""
    if not texto or texto == "unknown":
        return None

    try:
        d = datetime.strptime(texto, "%b %d %H:%M:%S %Y %Z")

        return d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def es_ip(nombre):
    try:
        import ipaddress

        ipaddress.ip_address(str(nombre).strip("[]"))

        return True
    except (ValueError, ImportError):
        return False


def match_hostname(info, nombre):
    """True, False, or None when there is nothing to check.

    ssl.match_hostname was removed in Python 3.12, so this is written out.
    None, not False, is returned for an IP target: in a scan almost every
    target is an address, and flagging a mismatch on each one would be noise
    rather than a finding."""
    if not nombre or es_ip(nombre):
        return None

    nombre = str(nombre).lower().rstrip(".")
    nombres = []

    for tipo, valor in info.get("subjectAltName", tuple()):
        if tipo == "DNS":
            nombres.append(str(valor).lower().rstrip("."))

    # the CN only counts when there is no SAN at all: that is what every
    # current client does
    if nombres == []:
        cn = campo(info.get("subject"), "commonName")

        if cn != "":
            nombres.append(cn.lower().rstrip("."))

    if nombres == []:
        return None

    for patron in nombres:
        if patron == nombre:
            return True

        # a wildcard only covers the leftmost label, and never a bare TLD
        if patron.startswith("*.") and patron.count(".") >= 2:
            cola = patron[1:]

            if nombre.endswith(cola) and nombre[: -len(cola)].count(".") == 0:
                return True

    return False


def verify_chain(host, port, sni=None, timeout=5):
    """Asks OpenSSL, which is what knows how to validate a chain.

    Gives back (estado, detalle): "trusted", or the reason it words it."""
    try:
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.load_default_certs()
        contexto.verify_mode = ssl.CERT_REQUIRED
        contexto.check_hostname = sni is not None and not es_ip(sni)

        sock = socket.create_connection((host, int(port)), timeout)

        try:
            with contexto.wrap_socket(sock, server_hostname=sni or host):
                return ("trusted", "")
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except ssl.SSLCertVerificationError as error:
        return ("untrusted", str(getattr(error, "verify_message", "") or error))
    except ssl.SSLError as error:
        return ("unknown", str(error))
    except (OSError, ValueError) as error:
        return ("unknown", str(error))


def inspect_socket(sock_ssl, sni=None):
    """Everything the already connected socket can tell, with no extra
    handshake. This is what makes scan -tlsinfo free: the handshake has
    happened anyway."""
    info = {}

    try:
        der = sock_ssl.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError, ValueError):
        der = None

    info = parse_der(der)

    try:
        info["tls_version"] = sock_ssl.version() or "unknown"
    except (ssl.SSLError, OSError):
        info["tls_version"] = "unknown"

    try:
        negociado = sock_ssl.cipher()
        info["cipher"] = negociado[0] if negociado else "unknown"
        info["cipher_bits"] = negociado[2] if negociado and len(negociado) > 2 else 0
    except (ssl.SSLError, OSError):
        info["cipher"] = "unknown"
        info["cipher_bits"] = 0

    # 3.13 and newer only; on anything older the chain is simply not reported
    try:
        cadena = sock_ssl.get_unverified_chain()
        info["chain_len"] = len(cadena) if cadena else 1
    except (AttributeError, ssl.SSLError, OSError, ValueError):
        info["chain_len"] = 0

    info["sni"] = sni or ""

    return info


def versiones_aceptadas(host, port, timeout=5):
    """One handshake per version. Three states, never two: a version this
    OpenSSL cannot offer is 'untested', which is NOT the same as the server
    having it switched off, and saying otherwise would be a lie in a report.

    SSLv2 and SSLv3 are never testable: OpenSSL 3 is built without them."""
    salida = []

    for nombre, atributo, bandera in _VERSIONES:
        if not getattr(ssl, bandera, False):
            salida.append((nombre, "untested", "not supported by the local OpenSSL"))
            continue

        version = getattr(ssl.TLSVersion, atributo, None)

        if version is None:
            salida.append((nombre, "untested", "not supported by the local OpenSSL"))
            continue

        try:
            contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            contexto.minimum_version = version
            contexto.maximum_version = version

            try:
                # without this the security level of OpenSSL 3 refuses the old
                # versions locally, and the result would read as if the server
                # had rejected them
                contexto.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass

            sock = socket.create_connection((host, int(port)), timeout)

            try:
                with contexto.wrap_socket(sock) as tls:
                    salida.append((nombre, "accepted", tls.cipher()[0] if tls.cipher() else ""))
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        except ssl.SSLError as error:
            texto = str(error)
            # the reason OpenSSL gives, not the "(_ssl.c:1082)" tail that
            # splitting on the last colon used to leave
            razon = getattr(error, "reason", "") or ""

            if razon == "":
                m = re.search(r"\[SSL:\s*([A-Z0-9_]+)\]", texto)
                razon = m.group(1) if m else texto.strip()

            # told apart so a local limit is never reported as a server one
            if razon in (
                "NO_PROTOCOLS_AVAILABLE",
                "UNSUPPORTED_PROTOCOL",
                "UNSAFE_LEGACY_RENEGOTIATION_DISABLED",
            ) or "no protocols available" in texto.lower():
                salida.append((nombre, "untested", "blocked by the local OpenSSL"))
            else:
                salida.append((nombre, "refused", razon))
        except (OSError, ValueError) as error:
            salida.append((nombre, "refused", str(error)))

    return salida


def _es_autofirmado(info):
    if info.get("issuer") and info.get("subject"):
        if info["issuer"] == info["subject"]:
            return True

    ski = info.get("ski", "")
    aki = info.get("aki", "")

    return ski != "" and ski == aki


def _vendor_defecto(info):
    """The name of a factory certificate, or "".

    Matched word by word and not by substring, or a legitimate
    sip.grandstreamreseller.com would be flagged. The caller also requires the
    certificate to be self signed: a name bought from a CA is somebody's real
    certificate, whatever brand it carries."""
    import re

    for clave, nombre in (
        ("commonName", info.get("subject")),
        ("organizationName", info.get("subject")),
        ("commonName", info.get("issuer")),
    ):
        texto = campo(nombre, clave).lower()

        if texto == "":
            continue

        palabras = set(re.split(r"[^a-z0-9]+", texto))
        palabras.add(re.sub(r"[^a-z0-9]", "", texto))

        for marca in _VENDOR_DEFECTO:
            if marca in palabras:
                return marca

    return ""


def findings(info, sni=None, trust=None):
    """(severidad, codigo, detalle) for everything worth reporting.

    Nothing here is a verdict on its own: a self signed certificate on an
    internal SIP trunk is normal. The caller prints that warning."""
    salida = []
    ahora = _ahora()

    desde = _fecha(info.get("notBefore", ""))
    hasta = _fecha(info.get("notAfter", ""))

    if hasta is not None:
        if hasta < ahora:
            salida.append(
                ("HIGH", "CERT_EXPIRED", "expired on %s" % info["notAfter"])
            )
        elif (hasta - ahora).days < 30:
            salida.append(
                (
                    "LOW",
                    "CERT_EXPIRES_SOON",
                    "expires in %d day(s)" % (hasta - ahora).days,
                )
            )

    if desde is not None and desde > ahora:
        salida.append(
            ("MEDIUM", "CERT_NOT_YET_VALID", "not valid before %s" % info["notBefore"])
        )

    if desde is not None and hasta is not None:
        dias = (hasta - desde).days

        if dias > 825 and not info.get("ca", False):
            salida.append(
                ("LOW", "CERT_LONG_VALIDITY", "valid for %d days" % dias)
            )

    if _es_autofirmado(info):
        salida.append(
            (
                "MEDIUM",
                "CERT_SELF_SIGNED",
                "issuer equals subject (%s)"
                % (texto_nombre(info.get("subject")) or "unknown"),
            )
        )
    elif trust is not None and trust[0] == "untrusted":
        salida.append(("MEDIUM", "CERT_UNTRUSTED", trust[1] or "chain not trusted"))

    # a factory certificate is always self signed. Requiring both keeps this
    # HIGH finding off a real certificate that a CA issued to a vendor name
    marca = _vendor_defecto(info) if _es_autofirmado(info) else ""

    if marca != "":
        salida.append(
            (
                "HIGH",
                "CERT_DEFAULT_VENDOR",
                "looks like a factory certificate (%s): its private key usually "
                "ships inside the firmware" % marca,
            )
        )

    coincide = match_hostname(info, sni)

    if coincide is False:
        salida.append(
            (
                "MEDIUM",
                "CERT_HOSTNAME_MISMATCH",
                "does not match %s" % sni,
            )
        )

    tipo = info.get("keytype", "unknown")
    bits = info.get("keybits", 0)

    if tipo == "RSA" or tipo == "DSA":
        if bits and bits < 1024:
            salida.append(("HIGH", "KEY_WEAK", "%s %d bits" % (tipo, bits)))
        elif bits and bits < 2048:
            salida.append(("MEDIUM", "KEY_WEAK", "%s %d bits" % (tipo, bits)))

        if tipo == "DSA":
            salida.append(("MEDIUM", "KEY_WEAK", "DSA key"))
    elif tipo == "EC" and bits and bits < 224:
        salida.append(("MEDIUM", "KEY_WEAK", "EC %d bits" % bits))

    firma = str(info.get("sigalg", "")).lower()

    for malo in _FIRMA_ALTA:
        if malo in firma:
            salida.append(("HIGH", "SIG_WEAK", info["sigalg"]))
            break
    else:
        for regular in _FIRMA_MEDIA:
            if regular in firma:
                salida.append(("MEDIUM", "SIG_WEAK", info["sigalg"]))
                break

    version = info.get("tls_version", "")

    if version in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
        salida.append(("MEDIUM", "TLS_OLD_VERSION", "negotiated %s" % version))

    cipher = str(info.get("cipher", ""))

    if cipher not in ("", "unknown"):
        for malo in _CIPHER_ALTO:
            if malo in cipher:
                salida.append(("HIGH", "CIPHER_WEAK", cipher))
                break
        else:
            for regular in _CIPHER_MEDIO:
                if regular in cipher:
                    salida.append(("MEDIUM", "CIPHER_WEAK", cipher))
                    break
            else:
                # no ephemeral key exchange means one stolen private key opens
                # every session that was ever recorded
                if (
                    version not in ("TLSv1.3",)
                    and "DHE" not in cipher
                    and cipher.startswith(("TLS_RSA", "AES", "RSA", "DES", "CAMELLIA"))
                ):
                    salida.append(
                        ("LOW", "NO_FORWARD_SECRECY", "%s has no (EC)DHE" % cipher)
                    )

    return salida


def fila(ip, port, info):
    """The ### row that RESULT_FIELDS['scan_tls'] expects."""
    return "###".join(
        str(x)
        for x in (
            ip,
            port,
            info.get("tls_version", ""),
            info.get("cipher", ""),
            info.get("cipher_bits", 0),
            "%s %s" % (info.get("keytype", ""), info.get("keybits", "") or ""),
            info.get("sigalg", ""),
            texto_nombre(info.get("subject")),
            texto_nombre(info.get("issuer")),
            info.get("notBefore", ""),
            info.get("notAfter", ""),
            ", ".join(
                v for t, v in info.get("subjectAltName", tuple()) if t in ("DNS", "IP Address")
            ),
            info.get("sha256", "")[:32],
            info.get("trust", ""),
        )
    )
