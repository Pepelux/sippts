#!/usr/bin/perl
# -=-=-=-=-=-=
# SipScan v1.2
# -=-=-=-=-=-=
#
# Pepelux <pepeluxx@gmail.com>
 
use warnings;
use strict;
use IO::Socket;
use IO::Socket::Timeout;
use NetAddr::IP;
use threads;
use threads::shared;
use Getopt::Long;
use Digest::MD5;

my $useragent = 'sipptk';
 
my $maxthreads = 300;
 
my $threads : shared = 0;
my $found : shared = 0;
my $count : shared = 0;
my $percent : shared = 0;
my @range;
my @results;
 
my $host = '';		# host
my $lport = '';		# local port
my $dport = '';		# destination port
my $from = '';		# source number
my $to = '';		# destination number
my $method = '';	# method to use (INVITE, REGISTER, OPTIONS)
my $v = 0;		# verbose mode
my $vv = 0;		# more verbose
my $user = '';		# auth user

my $to_ip = '';
my $from_ip = '';

my $tmpfile = "tmp/sipscan".time().".txt";
 
open(OUTPUT,">$tmpfile");
 
OUTPUT->autoflush(1);
STDOUT->autoflush(1);
 
sub init() {
    my $pini;
    my $pfin;
 
    # check params
    my $result = GetOptions ("h=s" => \$host,
				"m=s" => \$method,
				"d=s" => \$to,
				"s=s" => \$from,
				"ip=s" => \$from_ip,
				"u=s" => \$user,
				"l=s" => \$lport,
				"r=s" => \$dport,
				"v+" => \$v,
				"vv+" => \$vv);
 
	help() if ($host eq "");
 
	$lport = "5070" if ($lport eq "");
	$dport = "5060" if ($dport eq "");
	$user = "100" if ($user eq "");
	$from = $user if ($from eq "");
	$to = $user if ($to eq "");

	$method = uc($method);
	$method = "OPTIONS" if ($method eq "");
 
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
				}
			}
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

	if ($dport =~ /\-/) {
		$dport =~ /([0-9]*)-([0-9]*)/;
		$pini = $1;
		$pfin = $2;
	}
	else {
		$pini = $dport;
		$pfin = $dport;
	}

	my $nhost = @range;
 
	for (my $i = 0; $i <= $nhost; $i++) {
		for (my $j = $pini; $j <= $pfin; $j++) {
			while (1) {
				if ($threads < $maxthreads) {
					last unless defined($range[$i]);
					my $csec = 1;
					$from_ip = $range[$i] if ($from_ip eq "");
					my $thr = threads->new(\&scan, $range[$i], $from_ip, $lport, $j, $from, $to, $csec, $user);
					$thr->detach();
					$percent = ($count/($nhost*($pfin-$pini+1)))*100;
					$percent = sprintf("%.1f", $percent);

					last;
				}
				else {
					sleep(1);
				}
			}
		}
	}

	sleep(1);

	close(OUTPUT);

	open(OUTPUT, $tmpfile);
 
	print "\nIP:port\t\t\t  User-Agent\n";
	print "=======\t\t\t  ==========\n";

	my @results = <OUTPUT>;
	close (OUTPUT);

	unlink($tmpfile);

	@results = sort(@results);

	foreach(@results) {
		print $_;
	}

	print "\n";

	exit;
}

sub scan {
	my $to_ip = shift;
	my $from_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $csec = shift;
	my $user = shift;

	send_register($from_ip, $to_ip, $lport, $dport, $from, $to, $csec, $user) if ($method eq "REGISTER");
	send_invite($from_ip, $to_ip, $lport, $dport, $from, $to, $csec, $user) if ($method eq "INVITE");
	send_options($from_ip, $to_ip, $lport, $dport, $from, $to, $csec, $user) if ($method eq "OPTIONS");
}
 
# Send REGISTER message
sub send_register {
	{lock($count);$count++;}
	{lock($threads);$threads++;}
 
	my $from_ip = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $cseq = shift;
	my $user = shift;

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 5);
	IO::Socket::Timeout->enable_timeouts_on($sc);
	$sc->read_timeout(0.5);
	$sc->enable_timeout;
	$lport = $sc->sockport();

	my $branch = &generate_random_string(71, 0);
	my $callid = &generate_random_string(32, 1);
	
	my $msg = "REGISTER sip:".$to_ip." SIP/2.0\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\n";
	$msg .= "From: <sip:".$user."@".$to_ip.">;tag=0c26cd11\n";
	$msg .= "To: <sip:".$user."@".$to_ip.">\n";
	$msg .= "Contact: <sip:".$user."@".$from_ip.":$lport;transport=udp>\n";
	$msg .= "Call-ID: ".$callid."\n";
	$msg .= "CSeq: $cseq REGISTER\n";
	$msg .= "User-Agent: $useragent\n";
	$msg .= "Max-Forwards: 70\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\n";
	$msg .= "Expires: 10\n";
	$msg .= "Content-Length: 0\n\n";

	my $data = "";
	my $response = "";
	my $server = "";
	my $ua = "";
	my $line = "";

	if ($sc) {
		print $sc $msg;

		print "[+] $to_ip:$dport - Sending REGISTER $from => $to\n" if ($v eq 1);
		print "[+] $to_ip:$dport - Sending:\n=======\n$msg" if ($vv eq 1);

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					{lock($threads);$threads--;}
					return "";
				}

				$line = $_;
			
				if ($line =~ /^SIP\/2.0/ && $response eq "") {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}

				if ($line =~ /[Ss]erver/ && $server eq "") {
					$line =~ /[Ss]erver\:\s(.+)\r\n/;
 
					$server = $1 if ($1);
				}

				if ($line =~ /[Uu]ser\-[Aa]gent/ && $ua eq "") {
					$line =~ /[Uu]ser\-[Aa]gent\:\s(.+)\r\n/;
 
					$ua = $1 if ($1);
				}

				$data .= $line;
 
				if ($line =~ /^\r\n/) {
					print "[+] $to_ip:$dport - Sending REGISTER $from => $to\n" if ($v eq 0);
					print "[-] $response\n" if ($vv eq 0);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					last LOOP if ($response !~ /^1/);
				}
			}
		}
    
		if ($data ne "") {
			if ($server eq "") {
				$server = $ua;
			}
			else {
				if ($ua ne "") {
					$server .= " - $ua";
				}
			}

			my $dhost = "$to_ip:$dport";
			$dhost .= "\t" if (length($dhost) < 10);
			$server = "Unknown" if ($server eq "");
			print OUTPUT "$dhost\t| $server\n";
			{lock($found);$found++;}
		}
	}
	
	{lock($threads);$threads--;}
	
	return $response;
}

# Send INVITE message
sub send_invite {
	{lock($count);$count++;}
	{lock($threads);$threads++;}
 
	my $from_ip = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $cseq = shift;
	my $user = shift;

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 5);
	IO::Socket::Timeout->enable_timeouts_on($sc);
	$sc->read_timeout(0.5);
	$sc->enable_timeout;
	$lport = $sc->sockport();

	my $branch = &generate_random_string(71, 0);
	my $callid = &generate_random_string(32, 1);
	
	my $msg = "INVITE sip:".$to."@".$to_ip." SIP/2.0\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\n";
	$msg .= "From: \"$from\" <sip:".$user."@".$to_ip.">;tag=0c26cd11\n";
	$msg .= "To: <sip:".$to."@".$to_ip.">\n";
	$msg .= "Contact: <sip:".$from."@".$from_ip.":$lport;transport=udp>\n";
	$msg .= "Supported: replaces, timer, path\n";
	$msg .= "P-Early-Media: Supported\n";
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

	my $data = "";
	my $response = "";
	my $server = "";
	my $ua = "";
	my $line = "";

	if ($sc) {
		print $sc $msg;

		print "[+] $to_ip:$dport - Sending INVITE $from => $to\n" if ($v eq 1);
		print "[+] $to_ip:$dport - Sending:\n=======\n$msg" if ($vv eq 1);

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					{lock($threads);$threads--;}
					return "";
				}

				$line = $_;
			
				if ($line =~ /^SIP\/2.0/ && $response eq "") {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}

				if ($line =~ /[Ss]erver/ && $server eq "") {
					$line =~ /[Ss]erver\:\s(.+)\r\n/;
 
					$server = $1 if ($1);
				}

				if ($line =~ /[Uu]ser\-[Aa]gent/ && $ua eq "") {
					$line =~ /[Uu]ser\-[Aa]gent\:\s(.+)\r\n/;
 
					$ua = $1 if ($1);
				}

				$data .= $line;
 
				if ($line =~ /^\r\n/) {
					print "[+] $to_ip:$dport - Sending INVITE $from => $to\n" if ($v eq 0);
					print "[-] $response\n" if ($vv eq 0);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					last LOOP if ($response !~ /^1/);
				}
			}
		}
    
		if ($data ne "") {
			if ($server eq "") {
				$server = $ua;
			}
			else {
				if ($ua ne "") {
					$server .= " - $ua";
				}
			}

			my $dhost = "$to_ip:$dport";
			$dhost .= "\t" if (length($dhost) < 10);
			$server = "Unknown" if ($server eq "");
			print OUTPUT "$dhost\t| $server\n";
			{lock($found);$found++;}
		}
	}
	
	{lock($threads);$threads--;}
	
	return $response;
}

# Send OPTIONS message
sub send_options {
	{lock($count);$count++;}
	{lock($threads);$threads++;}
 
	my $from_ip = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $cseq = shift;
	my $user = shift;

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 5);
	IO::Socket::Timeout->enable_timeouts_on($sc);
	$sc->read_timeout(0.5);
	$sc->enable_timeout;
	$lport = $sc->sockport();

	my $branch = &generate_random_string(71, 0);
	my $callid = &generate_random_string(32, 1);
	
	my $msg = "OPTIONS sip:".$to."@".$to_ip." SIP/2.0\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\n";
	$msg .= "From: <sip:".$user."@".$to_ip.">;tag=0c26cd11\n";
	$msg .= "To: <sip:".$user."@".$to_ip.">\n";
	$msg .= "Contact: <sip:".$user."@".$from_ip.":$lport;transport=udp>\n";
	$msg .= "Call-ID: ".$callid."\n";
	$msg .= "CSeq: $cseq OPTIONS\n";
	$msg .= "User-Agent: $useragent\n";
	$msg .= "Max-Forwards: 70\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\n";
	$msg .= "Content-Length: 0\n\n";

	my $data = "";
	my $response = "";
	my $server = "";
	my $ua = "";
	my $line = "";

	if ($sc) {
		print $sc $msg;

		print "[+] $to_ip:$dport - Sending OPTIONS $from => $to\n" if ($v eq 1);
		print "[+] $to_ip:$dport - Sending:\n=======\n$msg" if ($vv eq 1);

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					{lock($threads);$threads--;}
					return "";
				}
				
				$line = $_;
			
				if ($line =~ /^SIP\/2.0/ && $response eq "") {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;
				
					if ($1) { $response = $1; }
				}

				if ($line =~ /[Ss]erver/ && $server eq "") {
					$line =~ /[Ss]erver\:\s(.+)\r\n/;
 
					$server = $1 if ($1);
				}

				if ($line =~ /[Uu]ser\-[Aa]gent/ && $ua eq "") {
					$line =~ /[Uu]ser\-[Aa]gent\:\s(.+)\r\n/;
 
					$ua = $1 if ($1);
				}

				$data .= $line;
 
				if ($line =~ /^\r\n/) {
					print "[+] $to_ip:$dport - Sending OPTIONS $from => $to\n" if ($v eq 0);
					print "[-] $response\n" if ($vv eq 0);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					last LOOP if ($response !~ /^1/);
				}
			}

			last LOOP;
		}
    
		if ($data ne "") {
			if ($server eq "") {
				$server = $ua;
			}
			else {
				if ($ua ne "") {
					$server .= " - $ua";
				}
			}

			my $dhost = "$to_ip:$dport";
			$dhost .= "\t" if (length($dhost) < 10);
			$server = "Unknown" if ($server eq "");
			print OUTPUT "$dhost\t| $server\n";
			{lock($found);$found++;}
		}
	}
	
	{lock($threads);$threads--;}
	
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
 
sub help {
    print qq{
SipSCAN v1.2 - by Pepelux <pepeluxx\@gmail.com>
------------

Usage: perl $0 -h <host> [options]
 
== Options ==
-m <string>      = Method: REGISTER/INVITE/OPTIONS (default: REGISTER)
-u  <string>     = Username
-s  <integer>    = Source number (CallerID) (default: 100)
-d  <integer>    = Destination number (default: 100)
-r  <integer>    = Remote port (default: 5060)
-ip <string>     = Source IP (by default it is the same as host)
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
 
== Examples ==
\$perl $0 -h 192.168.0.1
\tTo search SIP services on 192.168.0.1 port 5060 (using OPTIONS method)
\$perl $0 -h 192.168.0.1 -m INVITE
\tTo search SIP services on 192.168.0.1 port 5060 (using INVITE method)
\$perl $0 -h 192.168.0.0/24 -r 5060 -v
\tTo search SIP services on 192.168.0.0 port 5060 network (using OPTIONS method)
\$perl $0 -h 192.168.0.1-192.168.0.100 -r 5060-5070 -vv
\tTo search SIP services on 192.168.0.100 ports from 5060 to 5070 (using OPTIONS method)

};
 
    exit 1;
}
 
init();
