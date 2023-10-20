import random
import pyradamsa


def create_fuzzed_msg(all):
    rad = pyradamsa.Radamsa()

    methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
               'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']
    method = random.choice(methods)

    msg = ''

    direction = random.randint(0, 10)

    if direction < 3:
        direction = 'response'
    else:
        direction = 'request'

    withsdp = random.randint(0, 1)
    withvia = random.randint(0, 1)
    withroute = random.randint(0, 1)
    withrr = random.randint(0, 1)
    withdiversion = random.randint(0, 1)
    withpai = random.randint(0, 1)
    withct = random.randint(0, 1)
    withcd = random.randint(0, 1)
    withaccept = random.randint(0, 1)
    withse = random.randint(0, 1)
    withsupported = random.randint(0, 1)
    withmin = random.randint(0, 1)

    nvia = random.randint(0, 10)
    nroute = random.randint(0, 10)
    nrr = random.randint(0, 10)

    if direction == 'request':
        if all == 1:
            starting_line = method.encode() + b' ' + rad.fuzz(b'sip') + b':' + \
                rad.fuzz(b'100@sip.domain.com') + b' ' + \
                rad.fuzz(b'SIP/2.0') + b'\\r\\n'
        else:
            starting_line = method.encode() + b' sip:' + rad.fuzz(b'100') + b'@' + \
                rad.fuzz(b'sip.domain.com') + b'SIP/2.0' + b'\\r\\n'
    else:
        if all == 1:
            starting_line = rad.fuzz(
                b'SIP/2.0') + b' ' + rad.fuzz(b'200') + b' ' + rad.fuzz(b'OK') + b'\\r\\n'
        else:
            starting_line = b'SIP/2.0 ' + \
                rad.fuzz(b'200') + b' ' + rad.fuzz(b'OK') + b'\\r\\n'
    msg = starting_line

    if withvia:
        for i in range(0, nvia):
            if all == 1:
                hvia = b'Via: ' + rad.fuzz(b'SIP/2.0/UDP') + b' ' + rad.fuzz(
                    b'sip.domain.com:5060') + b';' + rad.fuzz(b'branch=bifpm0c0jdxwf8qvpu1') + b'\\r\\n'
            else:
                hvia = b'Via: SIP/2.0/' + rad.fuzz(b'UDP') + b' ' + rad.fuzz(b'sip.domain.com') + b':' + rad.fuzz(
                    b'5060') + b';branch=' + rad.fuzz(b'bifpm0c0jdxwf8qvpu1') + b'\\r\\n'
            msg += hvia

    if withroute:
        for i in range(0, nroute):
            if all == 1:
                route = b'Route: ' + \
                    rad.fuzz(b'<sip:1.2.3.4;lr;ftag=f8301e3f>') + b'\\r\\n'
            else:
                route = b'Route: <sip:' + rad.fuzz(b'1.2.3.4') + b';' + rad.fuzz(
                    b'lr') + b';ftag=' + rad.fuzz(b'f8301e3f') + b'>' + b'\\r\\n'
            msg += route

    if withrr:
        for i in range(0, nrr):
            if all == 1:
                rr = b'Record-Route: ' + \
                    rad.fuzz(
                        b'<sip:11.2.3.4;ftag=gK0a73adff;did=b7f.46c2>') + b'\\r\\n'
            else:
                rr = b'Record-Route: <sip:' + rad.fuzz(b'11.2.3.4') + b';ftag=' + rad.fuzz(
                    b'gK0a73adff') + b';did=' + rad.fuzz(b'b7f.46c2') + b'>' + b'\\r\\n'
            msg += rr

    if withdiversion:
        if all == 1:
            diversion = b'Diversion: ' + \
                rad.fuzz(
                    b'<sip:+1234567890@sip.domain.com>;reason=unconditional') + b'\\r\\n'
        else:
            diversion = b'Diversion: <sip:' + rad.fuzz(b'+1234567890') + b'@' + rad.fuzz(
                b'sip.domain.com') + b'>;reason=' + rad.fuzz(b'unconditional') + b'\\r\\n'
        msg += diversion

    if withpai:
        if all == 1:
            pai = b'P-Asserted-Identity: ' + \
                rad.fuzz(b'<sip:+0987654321@1.2.3.4;user=phone>') + b'\\r\\n'
        else:
            pai = b'P-Asserted-Identity: <sip:' + rad.fuzz(b'+0987654321') + b'@' + rad.fuzz(
                b'1.2.3.4') + b';user=' + rad.fuzz(b'phone>') + b'\\r\\n'
        msg += pai

    if withaccept:
        if all == 1:
            accept = b'Accept: ' + \
                rad.fuzz(
                    b'application/sdp, application/isup, application/dtmf, application/dtmf-relay,  multipart/mixed') + b'\\r\\n'
        else:
            accept = b'Accept: ' + rad.fuzz(b'application/sdp') + b', ' + rad.fuzz(b'application/isup') + b', ' + rad.fuzz(
                b'application/dtmf') + b', ' + rad.fuzz(b'application/dtmf-relay') + b', ' + rad.fuzz(b'multipart/mixed') + b'\\r\\n'
        msg += accept

    if withse:
        se = b'Session-Expires: ' + rad.fuzz(b'1800') + b'\\r\\n'
        msg += se

    if withsupported:
        if all == 1:
            supported = b'Supported: ' + rad.fuzz(b'timer,100rel') + b'\\r\\n'
        else:
            supported = b'Supported: ' + \
                rad.fuzz(b'timer') + b',' + rad.fuzz(b'100rel') + b'\\r\\n'
        msg += supported

    if withmin:
        min = b'Min-SE: ' + rad.fuzz(b'90') + b'\\r\\n'
        msg += min

    if all == 1:
        hfrom = b'From: ' + rad.fuzz(b'Bob') + b' ' + rad.fuzz(
            b'<sip:100@sip.domain.com>') + b';' + rad.fuzz(b'tag=1a2b3c4d') + b'\\r\\n'
    else:
        hfrom = b'From: ' + rad.fuzz(b'Bob') + b' <sip:' + rad.fuzz(b'100') + b'@' + rad.fuzz(
            b'sip.domain.com') + b'>;tag=' + rad.fuzz(b'1a2b3c4d') + b'\\r\\n'
    msg += hfrom

    if all == 1:
        hto = b'To: ' + rad.fuzz(b'Alice') + b' ' + rad.fuzz(
            b'<sip:200@sip.domain.com>') + b';' + rad.fuzz(b'tag=5e6f7g8h') + b'\\r\\n'
    else:
        hto = b'To: ' + rad.fuzz(b'Alice') + b' <sip:' + rad.fuzz(b'200') + b'@' + rad.fuzz(
            b'sip.domain.com') + b'>;tag=' + rad.fuzz(b'5e6f7g8h') + b'\\r\\n'
    msg += hto

    if all == 1:
        hcontact = b'Contact: ' + \
            rad.fuzz(b'<sip:100@1.2.3.4:5060') + b';' + \
            rad.fuzz(b'transport=udp>') + b'\\r\\n'
    else:
        hcontact = b'Contact: ' + b' <sip:' + rad.fuzz(b'100') + b'@' + rad.fuzz(
            b'1.2.3.4') + b'>;transport=' + rad.fuzz(b'udp') + b'>' + b'\\r\\n'
    msg += hcontact

    if withct:
        if all == 1:
            ct = b'Content-Type: ' + rad.fuzz(b'application/sdp') + b'\\r\\n'
        else:
            ct = b'Content-Type: ' + \
                rad.fuzz(b'application') + b'/' + rad.fuzz(b'sdp') + b'\\r\\n'
        msg += ct

    if withcd:
        if all == 1:
            cd = b'Content-Disposition: ' + \
                rad.fuzz(b'session; handling=required') + b'\\r\\n'
        else:
            cd = b'Content-Disposition: ' + \
                rad.fuzz(b'session') + b';handling=' + \
                rad.fuzz(b'required') + b'\\r\\n'
        msg += cd

    hcallid = b'Call-ID: ' + \
        rad.fuzz(b'a6e6daf17d3ea4db283dd6f0673c3df3') + b'\\r\\n'
    msg += hcallid

    if all == 1:
        hcseq = b'CSeq: ' + rad.fuzz(b'1') + b' ' + \
            rad.fuzz(method.encode()) + b'\\r\\n'
    else:
        hcseq = b'CSeq: ' + rad.fuzz(b'1') + b' ' + method.encode() + b'\\r\\n'
    msg += hcseq

    hmaxf = b'Max-Forwards: ' + rad.fuzz(b'70') + b'\\r\\n'
    msg += hmaxf

    hua = b'User-Agent: ' + rad.fuzz(b'Asterisk PBX 1.2.3/2~1') + b'\\r\\n'
    msg += hua

    if all == 1:
        hallow = b'Allow: ' + \
            rad.fuzz(
                b'INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE') + b'\\r\\n'
    else:
        hallow = b'Allow: ' + rad.fuzz(b'INVITE') + b',' + rad.fuzz(b'ACK') + b',' + rad.fuzz(b'CANCEL') + b',' + rad.fuzz(b'BYE') + b',' + rad.fuzz(b'NOTIFY') + b',' + rad.fuzz(b'REFER') + b',' + rad.fuzz(
            b'OPTIONS') + b',' + rad.fuzz(b'INFO') + b',' + rad.fuzz(b'SUBSCRIBE') + b',' + rad.fuzz(b'UPDATE') + b',' + rad.fuzz(b'PRACK') + b',' + rad.fuzz(b'MESSAGE') + b'\\r\\n'
    msg += hallow

    hexpires = b'Expires: ' + rad.fuzz(b'10') + b'\\r\\n'
    msg += hexpires

    if withsdp == 1:
        if all == 1:
            sdp = rad.fuzz(b'v=0') + b'\\r\\n'
            sdp += rad.fuzz(b'o=anonymous 1312841870 1312841870 IN IP4 1.2.3.4') + b'\\r\\n'
            sdp += rad.fuzz(b's=session') + b'\\r\\n'
            sdp += rad.fuzz(b'c=IN IP4 1.2.3.4') + b'\\r\\n'
            sdp += rad.fuzz(b't=0 0') + b'\\r\\n'
            sdp += rad.fuzz(b'm=audio 2362 RTP/AVP 0') + b'\\r\\n'
            sdp += rad.fuzz(b'a=rtpmap:18 G729/8000') + b'\\r\\n'
            sdp += rad.fuzz(b'a=rtpmap:0 PCMU/8000') + b'\\r\\n'
            sdp += rad.fuzz(b'a=rtpmap:8 PCMA/8000') + b'\\r\\n'
        else:
            sdp = b'v=' + rad.fuzz(b'0') + b'\\r\\n'
            sdp += b'o=' + rad.fuzz(b'anonymous') + b' ' + rad.fuzz(b'1312841870') + b' ' + rad.fuzz(
                b'1312841870') + b' ' + rad.fuzz(b'IN') + b' ' + rad.fuzz(b'IP4') + b' ' + rad.fuzz(b'1.2.3.4') + b'\\r\\n'
            sdp += b's=' + rad.fuzz(b'session') + b'\\r\\n'
            sdp += b'c=' + rad.fuzz(b'IN') + b' ' + rad.fuzz(b'IP4') + \
                b' ' + rad.fuzz(b'1.2.3.4') + b'\\r\\n'
            sdp += b't=' + rad.fuzz(b'0') + b' ' + rad.fuzz(b'0') + b'\\r\\n'
            sdp += b'm=' + rad.fuzz(b'audio') + b' ' + rad.fuzz(b'2362') + b' ' + rad.fuzz(
                b'RTP') + b'/' + rad.fuzz(b'AVP') + b' ' + rad.fuzz(b'0') + b'\\r\\n'
            sdp += b'a=' + rad.fuzz(b'rtpmap:') + rad.fuzz(b'18') + b' ' + \
                rad.fuzz(b'G729') + b'/' + rad.fuzz(b'8000') + b'\\r\\n'
            sdp += b'a=' + rad.fuzz(b'rtpmap:') + rad.fuzz(b'0') + b' ' + \
                rad.fuzz(b'PCMU') + b'/' + rad.fuzz(b'8000') + b'\\r\\n'
            sdp += b'a=' + rad.fuzz(b'rtpmap:') + rad.fuzz(b'8') + b' ' + \
                rad.fuzz(b'PCMA') + b'/' + rad.fuzz(b'8000') + b'\\r\\n'

        msg += b'Content-Length: ' + str(len(sdp)).encode() + b'\\r\\n'
        msg += sdp
    else:
        if all == 1:
            msg += b'Content-Length: ' + rad.fuzz(b'0') + b'\\r\\n'
        else:
            msg += b'Content-Length: 0' + b'\\r\\n'

    msg += b'\\r\\n'

    return msg
