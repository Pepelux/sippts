#!/usr/bin/perl
# -=-=-=-=-=-=-=
# SipINVITE v1.2
# -=-=-=-=-=-=-=
#
# Pepelux <pepeluxx@gmail.com>
 
use warnings;
use strict;
use IO::Socket;
use NetAddr::IP;
use Getopt::Long;
use Digest::MD5 qw(md5 md5_hex md5_base64);

my $useragent = 'sipptk';
 
my $host = '';	# host
my $lport = '';	# local port
my $dport = '';	# destination port
my $from = '';	# source number
my $to = '';	# destination number
my $refer = '';	# refer number
my $v = 0;	# verbose mode
my $user = '';	# auth user
my $pass = '';	# auth pass

my $realm = '';
my $nonce = '';
my $response = '';
my $digest = '';
 
my $to_ip = '';
my $from_ip = '';
 
sub init() {
	# check params
	my $result = GetOptions ("h=s" => \$host,
				"u=s" => \$user,
				"p=s" => \$pass,
				"d=s" => \$to,
				"s=s" => \$from,
				"ip=s" => \$from_ip,
				"l=s" => \$lport,
				"r=s" => \$dport,
				"t=s" => \$refer,
				"v+" => \$v);

	help() if ($host eq "" || $to eq "");

	$lport = "5070" if ($lport eq "");
	$dport = "5060" if ($dport eq "");
	$user = "100" if ($user eq "");
	$from = $user if ($from eq "");

	$to_ip = inet_ntoa(inet_aton($host));
	$from_ip = $to_ip if ($from_ip eq "");

	my $callid = &generate_random_string(32, 1);
	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 10);

	# first INVITE
	my $csec = 1;
	my $res = send_invite($sc, $from_ip, $to_ip, $lport, $dport, $from, $to, $digest, $callid, $csec, $user);

	# Authentication
	if (($res =~ /^401/ || $res =~ /^407/) && $user ne '' && $pass ne '') { 
		my $uri = "sip:$to\@$to_ip";
		my $a = md5_hex($user.':'.$realm.':'.$pass);
		my $b = md5_hex('INVITE:'.$uri);
		my $r = md5_hex($a.':'.$nonce.':'.$b);
		$digest = "username=\"$user\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\", response=\"$r\", algorithm=MD5";

		$res = send_ack($sc, $from_ip, $to_ip, $lport, $dport, $from, $to, "", $callid, $csec);
		$csec++;
		$res = send_invite($sc, $from_ip, $to_ip, $lport, $dport, $from, $to, $digest, $callid, $csec, $user);
	}

	# Transfer call
	if ($res =~ /^200/ && $refer ne "") {
		$csec++;
		$res = send_ack($sc, $from_ip, $to_ip, $lport, $dport, $from, $to, $digest, $callid, $csec);
		$csec++;
		$res = send_refer($sc, $from_ip, $to_ip, $lport, $dport, $from, $to, $digest, $callid, $csec, $user, $refer);
	}

	exit;
}


# Send INVITE message
sub send_invite {
	my $sc = shift;
	my $from_ip = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $digest = shift;
	my $callid = shift;
	my $cseq = shift;
	my $user = shift;
	
	my $branch = &generate_random_string(71, 0);
	
	my $msg = "INVITE sip:".$to."@".$to_ip." SIP/2.0\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\n";
	$msg .= "From: \"$from\" <sip:".$user."@".$to_ip.">;tag=0c26cd11\n";
	$msg .= "To: <sip:".$to."@".$to_ip.">\n";
	$msg .= "Contact: <sip:".$from."@".$from_ip.":$lport;transport=udp>\n";
	$msg .= "Authorization: Digest $digest\n" if ($digest ne "");
	$msg .= "Call-ID: ".$callid."\n";
	$msg .= "CSeq: $cseq INVITE\n";
	$msg .= "User-Agent: $useragent\n";
	$msg .= "Max-Forwards: 70\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\n";
	$msg .= "Content-Type: application/sdp\n";

	my $sdp .= "v=0\n";
	$sdp .= "o=anonymous 1312841870 1312841870 IN IP4 $from_ip\n";
	$sdp .= "s=session\n";
	$sdp .= "c=IN IP4 $from_ip\n";
	$sdp .= "t=0 0\n";
	$sdp .= "m=audio 2362 RTP/AVP 0\n";
	$sdp .= "a=rtpmap:18 G729/8000\n";
	$sdp .= "a=rtpmap:0 PCMU/8000\n";
	$sdp .= "a=rtpmap:8 PCMA/8000\n";

	$msg .= "Content-Length: ".length($sdp)."\n\n";
	$msg .= $sdp;

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending INVITE $from => $to\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";

	LOOP: {
		while (<$sc>) {
			$line = $_;
			
			if ($line =~ /^SIP\/2.0/ && $response eq "") {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
				if ($1) { $response = $1; }
			}
				
			if ($line =~ /^WWW-Authenticate:/ || $line =~ /^Proxy-Authenticate:/) {
				$line =~ /^WWW-Authenticate:\sDigest\salgorithm=(.+),\srealm=\"(.+)\",\snonce=\"(.+)\"\r\n/ if ($line =~ /^WWW-Authenticate:/);
				$line =~ /^Proxy-Authenticate:\sDigest\salgorithm=(.+),\srealm=\"(.+)\",\snonce=\"(.+)\"\r\n/ if ($line =~ /^Proxy-Authenticate:/);
				$realm = $2 if ($2);
				$nonce = $3 if ($3);
			}
 
			$data .= $line;
 
			if ($line =~ /^\r\n/) {
				if ($v eq 0) { print "[-] $response\n"; }
				else { print "Receiving:\n=========\n$data"; }

				last LOOP if ($response !~ /^1/);

				$data = "";
				$response = "";
			}
		}
	}
    
	return $response;
}

# Send ACK message
sub send_ack {
	my $sc = shift;
	my $from_ip = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $digest = shift;
	my $callid = shift;
	my $cseq = shift;
	
	my $branch = &generate_random_string(71, 0);
	
	my $msg = "ACK sip:".$to."@".$to_ip." SIP/2.0\n";
	$msg .= "To: $to <sip:".$to."@".$to_ip.">\n";
	$msg .= "From: $from <sip:".$from."@".$from_ip.">;tag=0c26cd11\n";
	$msg .= "Via: SIP/2.0/UDP $to_ip:$lport;branch=$branch;rport\n";
	$msg .= "Call-ID: ".$callid."\n";
	$msg .= "CSeq: $cseq ACK\n";
	$msg .= "Contact: <sip:".$to."@".$to_ip.":$lport>\n";
	$msg .= "Authorization: Digest $digest\n" if ($digest ne "");
	$msg .= "User-Agent: $useragent\n";
	$msg .= "Max-Forwards: 70\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\n";
	$msg .= "Content-Length: 0\n\n";

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending ACK\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";

	if ($digest ne "") {
	LOOP: {
		while (<$sc>) {
			$line = $_;
			
			if ($line =~ /^SIP\/2.0/ && $response eq "") {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
				if ($1) { $response = $1; }
			}
				
			$data .= $line;
 
			if ($line =~ /^\r\n/) {
				if ($v eq 0) { print "[-] $response\n"; }
				else { print "Receiving:\n=========\n$data"; }

				last LOOP if ($response !~ /^1/);

				$data = "";
				$response = "";
			}
		}
	}
	}
    
	return $response;
}

# Send REFER message
sub send_refer {
	my $sc = shift;
	my $from_ip = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $digest = shift;
	my $callid = shift;
	my $cseq = shift;
	my $user = shift;
	my $referto = shift;
	
	my $branch = &generate_random_string(71, 0);

	my $msg = "REFER sip:".$to."@".$to_ip." SIP/2.0\n";
	$msg .= "To: $to <sip:".$to."@".$to_ip.">\n";
	$msg .= "From: $user <sip:".$user."@".$to_ip.">;tag=0c26cd11\n";
	$msg .= "Via: SIP/2.0/UDP $to_ip:$lport;branch=$branch;rport\n";
	$msg .= "Call-ID: ".$callid."\n";
	$msg .= "CSeq: $cseq REFER\n";
	$msg .= "Contact: <sip:".$user."@".$from_ip.":$lport>\n";
	$msg .= "Authorization: Digest $digest\n" if ($digest ne "");
	$msg .= "User-Agent: $useragent\n";
	$msg .= "Max-Forwards: 70\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\n";
	$msg .= "Refer-To: <sip:".$referto."@".$to_ip.">\n";
	$msg .= "Referred-By: <sip:".$user."@".$from_ip.":$lport>\n";
	$msg .= "Content-Length: 0\n\n";

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending REFER $from => $referto\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";

	LOOP: {
		while (<$sc>) {
			$line = $_;
			
			if ($line =~ /^SIP\/2.0/ && $response eq "") {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
				if ($1) { $response = $1; }
			}
				
			$data .= $line;
 
			if ($line =~ /^\r\n/) {
				if ($v eq 0) { print "[-] $response\n"; }
				else { print "Receiving:\n=========\n$data"; }

				last LOOP if ($response !~ /^1/);

				$data = "";
				$response = "";
			}
		}
	}
    
	return $response;
}

# Generate a random string
sub generate_random_string {
	my $length_of_randomstring = shift;
	my $only_hex = shift;
	my @chars;

	if ($only_hex == 0) {
		@chars = ('a'..'z','0'..'9');
	}
	else {
		@chars = ('a'..'f','0'..'9');
	}

	my $random_string;

	foreach (1..$length_of_randomstring) {
		$random_string.=$chars[rand @chars];
	}

	return $random_string;
}
 
sub help {
    print qq{
SipINVITE v1.2 - by Pepelux <pepeluxx\@gmail.com>
--------------

Usage: perl $0 -h <host> -d <dst_number> [options]
 
== Options ==
-d  <integer>    = Destination number
-u  <string>     = Username to authenticate
-p  <string>     = Password to authenticate
-s  <integer>    = Source number (CallerID) (default: 100)
-r  <integer>    = Remote port (default: 5060)
-t  <integer>    = Transfer call to another number
-ip <string>     = Source IP (by default it is the same as host)
-v               = Verbose (trace information)
 
== Examples ==
\$perl $0 -h 192.168.0.1 -d 100
\tTrying to make a call to exten 100 (without auth)
\$perl $0 -h 192.168.0.1 -u sipuser -p supersecret -d 100 -r 5080
\tTrying to make a call to exten 100 (with auth)
\$perl $0 -h 192.168.0.1 -s 200 -d 555555555 -v
\tTrying to make a call to number 555555555 (without auth) with source number 200
\$perl $0 -h 192.168.0.1 -d 555555555 -t 666666666
\tTrying to make a call to number 555555555 (without auth) and tranfer it to number 666666666
\$perl $0 -h 192.168.0.1 -d 555555555 -t 666666666 -s 123456789
\tTrying to make a call to number 555555555 (without auth) using callerid 123456789 and tranfer it to number 666666666
 
};
 
    exit 1;
}
 
init();
