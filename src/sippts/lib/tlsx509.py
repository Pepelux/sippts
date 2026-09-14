#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.2"
__license__ = "GPL"
__copyright__ = "Copyright 2015-2026, SIPPTS"
__email__ = "pepeluxx@gmail.com"

"""A small DER reader for the parts of an X.509 certificate that a SIP audit
needs. It is NOT a general X.509 implementation and it does not validate
anything: OpenSSL does the validating, this only reads.

Why it exists: with verify_mode = CERT_NONE, which is what sippts uses because
it audits instead of connecting, getpeercert() hands back an empty dict.
getpeercert(binary_form=True) does give the DER, and nothing in the standard
library turns that DER into fields. ssl._ssl._test_decode_cert() comes close
but it is private, it needs the certificate written to a file, and it reports
neither the key size nor the signature algorithm, which are exactly the two
things the weak key and weak signature findings are about.

Everything here is wrapped so that a certificate this cannot read gives back
"unknown" instead of taking a scan down with it.
"""

import hashlib


# tags
_SEQUENCE = 0x30
_SET = 0x31
_INTEGER = 0x02
_BIT_STRING = 0x03
_OCTET_STRING = 0x04
_NULL = 0x05
_OID = 0x06
_UTF8 = 0x0C
_PRINTABLE = 0x13
_IA5 = 0x16
_UTCTIME = 0x17
_GENTIME = 0x18

_MESES = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

# the names getpeercert() uses, so that what comes out of here can be dropped
# in wherever a getpeercert() dict was expected
_OIDS_NOMBRE = {
    "2.5.4.3": "commonName",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.5": "serialNumber",
    "2.5.4.4": "surname",
    "2.5.4.42": "givenName",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "domainComponent",
    "2.5.4.97": "organizationIdentifier",
    "2.5.4.9": "streetAddress",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.15": "businessCategory",
    "2.5.4.17": "postalCode",
    "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionLocalityName",
    "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionStateOrProvinceName",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionCountryName",
    "0.9.2342.19200300.100.1.1": "userId",
}

_OIDS_FIRMA = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}

_OIDS_CLAVE = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

# curve -> size in bits, to say something useful about an EC key
_OIDS_CURVA = {
    "1.2.840.10045.3.1.1": ("prime192v1", 192),
    "1.3.132.0.33": ("secp224r1", 224),
    "1.2.840.10045.3.1.7": ("prime256v1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}

_OID_SAN = "2.5.29.17"
_OID_BASIC = "2.5.29.19"
_OID_SKI = "2.5.29.14"
_OID_AKI = "2.5.29.35"


def _leer_tlv(buf, i):
    """One tag-length-value at position i. Gives (tag, inicio, fin, siguiente)."""
    tag = buf[i]
    i += 1
    largo = buf[i]
    i += 1

    if largo & 0x80:
        octetos = largo & 0x7F

        if octetos == 0 or octetos > 4:
            raise ValueError("indefinite or oversized length")

        largo = int.from_bytes(buf[i : i + octetos], "big")
        i += octetos

    return (tag, i, i + largo, i + largo)


def _oid(raw):
    """DER OID bytes -> dotted string."""
    if raw == b"":
        return ""

    primero = raw[0]
    partes = [str(primero // 40), str(primero % 40)]
    valor = 0

    for b in raw[1:]:
        valor = (valor << 7) | (b & 0x7F)

        if not b & 0x80:
            partes.append(str(valor))
            valor = 0

    return ".".join(partes)


def _texto(raw):
    for codec in ("utf-8", "latin-1"):
        try:
            return raw.decode(codec).strip()
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", "replace").strip()


def _fecha(tag, raw):
    """UTCTime or GeneralizedTime -> the 'Jun  1 12:00:00 2026 GMT' that
    getpeercert() produces, so both can be compared the same way."""
    t = _texto(raw)

    if tag == _UTCTIME:
        # two digit year, and RFC 5280 puts the pivot at 50
        anio = int(t[0:2])
        anio += 2000 if anio < 50 else 1900
        resto = t[2:]
    else:
        anio = int(t[0:4])
        resto = t[4:]

    mes = int(resto[0:2])
    dia = int(resto[2:4])
    hora = resto[4:6] if len(resto) >= 6 else "00"
    minuto = resto[6:8] if len(resto) >= 8 else "00"
    segundo = resto[8:10] if len(resto) >= 10 else "00"

    return "%s %2d %s:%s:%s %d GMT" % (
        _MESES[mes - 1],
        dia,
        hora,
        minuto,
        segundo,
        anio,
    )


def _nombre(buf, ini, fin):
    """RDNSequence -> the tuple of tuples that getpeercert() gives back."""
    salida = []
    i = ini

    while i < fin:
        tag, rini, rfin, sig = _leer_tlv(buf, i)
        i = sig

        if tag != _SET:
            continue

        j = rini

        while j < rfin:
            tag2, aini, afin, sig2 = _leer_tlv(buf, j)
            j = sig2

            if tag2 != _SEQUENCE:
                continue

            k = aini
            tag3, oini, ofin, sig3 = _leer_tlv(buf, k)
            oid = _oid(buf[oini:ofin])
            k = sig3

            if k >= afin:
                continue

            tag4, vini, vfin, _ = _leer_tlv(buf, k)
            nombre = _OIDS_NOMBRE.get(oid, oid)
            salida.append(((nombre, _texto(buf[vini:vfin])),))

    return tuple(salida)


def _clave(buf, ini, fin):
    """SubjectPublicKeyInfo -> (type, bits, curve)."""
    i = ini
    tag, aini, afin, sig = _leer_tlv(buf, i)  # AlgorithmIdentifier

    if tag != _SEQUENCE:
        return ("unknown", 0, "")

    tag2, oini, ofin, sig2 = _leer_tlv(buf, aini)
    oid = _oid(buf[oini:ofin])
    tipo = _OIDS_CLAVE.get(oid, oid)
    curva = ""

    if tipo == "EC" and sig2 < afin:
        tag3, cini, cfin, _ = _leer_tlv(buf, sig2)

        if tag3 == _OID:
            nombre, bits = _OIDS_CURVA.get(_oid(buf[cini:cfin]), ("", 0))

            if nombre != "":
                return ("EC", bits, nombre)

            curva = _oid(buf[cini:cfin])

    if tipo in ("Ed25519", "Ed448"):
        return (tipo, 256 if tipo == "Ed25519" else 456, "")

    # the BIT STRING that holds the key itself
    tag4, bini, bfin, _ = _leer_tlv(buf, sig)

    if tag4 != _BIT_STRING:
        return (tipo, 0, curva)

    datos = buf[bini + 1 : bfin]  # the first byte counts the unused bits

    if tipo in ("RSA", "DSA"):
        try:
            tag5, sini, sfin, _ = _leer_tlv(datos, 0)

            if tag5 == _SEQUENCE:
                tag6, mini, mfin, _ = _leer_tlv(datos, sini)

                if tag6 == _INTEGER:
                    # the real size of the modulus, so a 2048 bit key that DER
                    # stores in 257 bytes with a leading zero is not read as
                    # 2056
                    return (
                        tipo,
                        int.from_bytes(datos[mini:mfin], "big").bit_length(),
                        curva,
                    )
        except (ValueError, IndexError):
            pass

    return (tipo, 0, curva)


def _san(buf, ini, fin):
    """GeneralNames -> the subjectAltName of getpeercert()."""
    salida = []
    tag, sini, sfin, _ = _leer_tlv(buf, ini)

    if tag != _SEQUENCE:
        return tuple()

    i = sini

    while i < sfin:
        t, vini, vfin, sig = _leer_tlv(buf, i)
        i = sig

        if t == 0x82:  # dNSName
            salida.append(("DNS", _texto(buf[vini:vfin])))
        elif t == 0x87:  # iPAddress
            raw = buf[vini:vfin]

            if len(raw) == 4:
                salida.append(("IP Address", ".".join(str(b) for b in raw)))
            elif len(raw) == 16:
                grupos = [
                    "%x" % int.from_bytes(raw[j : j + 2], "big")
                    for j in range(0, 16, 2)
                ]
                salida.append(("IP Address", ":".join(grupos)))
        elif t == 0x81:  # rfc822Name
            salida.append(("email", _texto(buf[vini:vfin])))
        elif t == 0x86:  # uniformResourceIdentifier
            salida.append(("URI", _texto(buf[vini:vfin])))
        elif t == 0xA4:
            # directoryName: [4] wraps a Name, and a Name is a SEQUENCE of
            # RDNs, so the outer SEQUENCE has to be opened before reading it
            try:
                tn, nini, nfin, _ = _leer_tlv(buf, vini)

                if tn == _SEQUENCE:
                    salida.append(("DirName", _nombre(buf, nini, nfin)))
            except (ValueError, IndexError):
                pass

    return tuple(salida)


def _extensiones(buf, ini, fin, info):
    tag, sini, sfin, _ = _leer_tlv(buf, ini)

    if tag != _SEQUENCE:
        return

    i = sini

    while i < sfin:
        t, eini, efin, sig = _leer_tlv(buf, i)
        i = sig

        if t != _SEQUENCE:
            continue

        j = eini
        t2, oini, ofin, sig2 = _leer_tlv(buf, j)

        if t2 != _OID:
            continue

        oid = _oid(buf[oini:ofin])
        j = sig2

        # the optional critical BOOLEAN sits between the OID and the value
        if j < efin and buf[j] == 0x01:
            _, _, _, j = _leer_tlv(buf, j)

        if j >= efin:
            continue

        t3, vini, vfin, _ = _leer_tlv(buf, j)

        if t3 != _OCTET_STRING:
            continue

        try:
            if oid == _OID_SAN:
                info["subjectAltName"] = _san(buf, vini, vfin)
            elif oid == _OID_BASIC:
                t4, bini, bfin, _ = _leer_tlv(buf, vini)

                if t4 == _SEQUENCE and bini < bfin and buf[bini] == 0x01:
                    _, cini, cfin, _ = _leer_tlv(buf, bini)
                    info["ca"] = buf[cini:cfin] not in (b"\x00", b"")
            elif oid == _OID_SKI:
                t4, kini, kfin, _ = _leer_tlv(buf, vini)
                info["ski"] = buf[kini:kfin].hex()
            elif oid == _OID_AKI:
                t4, kini, kfin, _ = _leer_tlv(buf, vini)
                k = kini

                while k < kfin:
                    t5, aini, afin, sig3 = _leer_tlv(buf, k)
                    k = sig3

                    if t5 == 0x80:
                        info["aki"] = buf[aini:afin].hex()
                        break
        except (ValueError, IndexError):
            continue


def parse_der(der):
    """DER bytes -> a dict shaped like getpeercert(), plus what that one does
    not report: sigalg, keytype, keybits, curve, sha256, ca, ski and aki.

    Never raises: whatever cannot be read comes back as "unknown" or empty."""
    info = {
        "version": 0,
        "serialNumber": "unknown",
        "notBefore": "unknown",
        "notAfter": "unknown",
        "subject": tuple(),
        "issuer": tuple(),
        "subjectAltName": tuple(),
        "sigalg": "unknown",
        "keytype": "unknown",
        "keybits": 0,
        "curve": "",
        "sha256": "",
        "ca": False,
        "ski": "",
        "aki": "",
    }

    if not der:
        return info

    try:
        info["sha256"] = hashlib.sha256(der).hexdigest()

        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }
        tag, cini, cfin, _ = _leer_tlv(der, 0)

        if tag != _SEQUENCE:
            return info

        tag, tini, tfin, sig_tbs = _leer_tlv(der, cini)

        if tag != _SEQUENCE:
            return info

        # signatureAlgorithm, the one of the outer SEQUENCE
        try:
            t, aini, afin, _ = _leer_tlv(der, sig_tbs)

            if t == _SEQUENCE:
                t2, oini, ofin, _ = _leer_tlv(der, aini)
                oid = _oid(der[oini:ofin])
                info["sigalg"] = _OIDS_FIRMA.get(oid, oid)
        except (ValueError, IndexError):
            pass

        i = tini

        # [0] EXPLICIT version, optional and absent on a v1 certificate
        if der[i] == 0xA0:
            t, vini, vfin, sig = _leer_tlv(der, i)

            try:
                t2, nini, nfin, _ = _leer_tlv(der, vini)
                info["version"] = int.from_bytes(der[nini:nfin], "big") + 1
            except (ValueError, IndexError):
                info["version"] = 3

            i = sig
        else:
            info["version"] = 1

        # serialNumber
        t, sini, sfin, i = _leer_tlv(der, i)
        serie = int.from_bytes(der[sini:sfin], "big")
        texto = "%X" % serie
        # OpenSSL pads it to an even number of hex digits, and getpeercert()
        # shows it that way: without this a serial starting with a nibble
        # under 0x10 comes out one character short
        info["serialNumber"] = texto if len(texto) % 2 == 0 else "0" + texto

        # signature (the inner copy), skipped
        t, _, _, i = _leer_tlv(der, i)

        # issuer
        t, iini, ifin, i = _leer_tlv(der, i)
        info["issuer"] = _nombre(der, iini, ifin)

        # validity
        t, vini, vfin, i = _leer_tlv(der, i)
        j = vini

        for clave in ("notBefore", "notAfter"):
            if j >= vfin:
                break

            t2, fini, ffin, j = _leer_tlv(der, j)

            try:
                info[clave] = _fecha(t2, der[fini:ffin])
            except (ValueError, IndexError):
                info[clave] = "unknown"

        # subject
        t, subini, subfin, i = _leer_tlv(der, i)
        info["subject"] = _nombre(der, subini, subfin)

        # subjectPublicKeyInfo
        t, kini, kfin, i = _leer_tlv(der, i)
        tipo, bits, curva = _clave(der, kini, kfin)
        info["keytype"] = tipo
        info["keybits"] = bits
        info["curve"] = curva

        # the optional [1] [2] [3] that follow; only [3] carries extensions
        while i < tfin:
            t, eini, efin, sig = _leer_tlv(der, i)
            i = sig

            if t == 0xA3:
                _extensiones(der, eini, efin, info)
    except (ValueError, IndexError, KeyError):
        # a certificate this cannot read must not take a scan down
        pass

    return info


def campo(nombre, clave):
    """Pulls one field out of a subject or issuer tuple, e.g. commonName."""
    for rdn in nombre or tuple():
        for par in rdn:
            if len(par) == 2 and par[0] == clave:
                return par[1]

    return ""


def texto_nombre(nombre):
    """A subject or an issuer on one line, for a table."""
    partes = []

    for etiqueta, clave in (
        ("CN", "commonName"),
        ("O", "organizationName"),
        ("OU", "organizationalUnitName"),
        ("C", "countryName"),
    ):
        valor = campo(nombre, clave)

        if valor != "":
            partes.append("%s=%s" % (etiqueta, valor))

    return ", ".join(partes)
