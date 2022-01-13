#!/usr/bin/perl
#
# -=-=-=-
# SipScan
# -=-=-=-
#
# Sipscan works sending and waiting well-formed SIP packages. For example, Nmap
# is a great tool for scanning networks, but over UDP it is better and faster 
# to send well-formed SIP packages and wait valid responses.
# Sipscan tries, by default, to connect over the UDP protocol. If the connection
# fails, it will try over TCP. You can also force to use only over UDP or TCP.
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
use DBI;
use File::Temp qw(tempfile);

my $useragent = 'pplsip';

my $threads = 0;
my @range;
my @results;
 
my $maxthreads = 300;
my $host = ''; # host
my $dport = '5060'; # destination port for UDP and TCP
my $tlsport = '5061'; # destination port for TLS
my $method = 'OPTIONS'; # method to use (INVITE, REGISTER, OPTIONS)
my $fromuser = '100'; # From User
my $fromname = ''; # From Name
my $touser = '100'; # To User
my $toname = ''; # To Name
my $contactdomain = '1.1.1.1'; # Contact Domain
my $domain = ''; # SIP Domain
my $v = 0; # verbose mode
my $vv = 0; # more verbose
my $nolog = 0; # no log
my $proto = '';	# protocol
my $withdb = 0; # save results into a SQLite database
my $noth = 0; # don't use threads
my $web = 0; # check for a web control panel
my $ver = 0; # show version

my $abort = 0;

my $to_ip = '';
my $from_ip = '';

my $db;
my $hostsid;

my $data_path = "/usr/share/sippts/";
$data_path = "./" if !(-e $data_path . "sippts_empty.db");
my $tmpfile = new File::Temp( UNLINK => 0 );

open(OUTPUT,">$tmpfile");
 
OUTPUT->autoflush(1);
STDOUT->autoflush(1);

$SIG{INT} = \&interrupt;

sub prepare_db() {
	my $database = $data_path . "sippts.db";
	my $database_empty = $data_path . "sippts_empty.db";

	unless (-e $database || -e $database_empty) {
		die("Database $database not found\n\n");
	}

	system("cp $database_empty $database") if (! -e $database);
	
	$db = DBI->connect("dbi:SQLite:dbname=$database","","") or die $DBI::errstr;
	$hostsid = last_id();
}

sub init() {
    my $pini;
    my $pfin;
 
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
				"db+" => \$withdb,
				"nolog+" => \$nolog,
				"web+" => \$web,
				"ua=s" => \$useragent,
				"noth+" => \$noth,
				"th=s" => \$maxthreads,
				"version+" => \$ver,
				"v+" => \$v,
				"vv+" => \$vv);
 
	check_version() if ($ver eq 1);
	help() if ($host eq "");

	prepare_db() if ($withdb eq 1);

	$proto = lc($proto);
	$proto = "all" if ($proto ne "tcp" && $proto ne "udp" && $proto ne "tls");
	$maxthreads = 1 if ($noth eq 1);
	$method = uc($method);
 
	my @hostlist;

	if ($host !~ /[\,]+/ && $host !~ /\d+\.\d+\.\d+\.\d+/) {
		$host = inet_ntoa(inet_aton($host));
	}

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
				
							$ip2_4 = 1;
						}
				
						$ip2_3 = 1;
					}
				
					$ip2_2 = 1;
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
	        my $decimal_ini = ip2num($1);
    	    my $decimal_end = ip2num($2);

	        for ( my $i = $decimal_ini ; $i <= $decimal_end ; $i++ ) {
    	    	my $ipaddr = num2ip($i);
				push @range, $ipaddr;
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
				push @range, $ip->addr;
			}
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
 	my @arrow = ("|", "/", "-", "\\");
	my $cont = 0;

	for (my $i = 0; $i < $nhost; $i++) {
		for (my $j = $pini; $j <= $pfin; $j++) {
			while (1) {
				if ($threads < $maxthreads) {
					last unless defined($range[$i]);
					my $csec = 1;
					$from_ip = $range[$i] if ($from_ip eq "");
					my $sipdomain = $domain;
					$sipdomain = $range[$i] if ($domain eq "");
					print "\r[".$arrow[$cont]."] Scanning ".$range[$i].":$j ...";

					if ($maxthreads > 1) {
						threads->create(\&scan, $range[$i], $j, $contactdomain, $fromuser, $fromname, $touser, $toname, $csec, $proto, $sipdomain);
						$threads++;

						$cont++;
						$cont = 0 if ($cont > 3);
					}
					else{
						scan($range[$i], $j, $contactdomain, $fromuser, $fromname, $touser, $toname, $csec, $proto, $sipdomain);
					} 

					last;
				}
				else {
					# Wait for threads to all finish processing.
					foreach my $thr (threads->list()) {
						$thr->join();
					}

					$threads = 0;
				}
			}
		}
	}

	# Wait for threads to all finish processing.
	foreach my $thr (threads->list()) {
		$thr->join();
	}

	close(OUTPUT);

	showres();
	unlink($tmpfile);

	exit;
}

sub save {
	my $line = shift;

	$line =~ s/\n//g;
	my @lines = split (/\t/, $line);
	my $sth = $db->prepare("SELECT id FROM hosts WHERE host='".$lines[0]."'") or die "Couldn't prepare statement: " . $db->errstr;
	$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
	my @data = $sth->fetchrow_array();
	my $sql;
	$sth->finish;

	$lines[4] = '' if !($lines[4]);

	if ($#data < 0) {
		$sql = "INSERT INTO hosts (id, host, port, proto, useragent, web) VALUES ($hostsid, '".$lines[0]."', ".$lines[1].", '".$lines[2]."', '".$lines[3]."','".$lines[4]."')";
		$db->do($sql);
		$hostsid = $db->func('last_insert_rowid') + 1;
	}
	else {
		$sql = "UPDATE hosts SET port=".$lines[1].", proto='".$lines[2]."', useragent='".$lines[3]."', web='".$lines[4]."' WHERE host='".$lines[0]."'";
		$db->do($sql);
	}
}

sub last_id {
	my $sth = $db->prepare('SELECT id FROM hosts ORDER BY id DESC LIMIT 1') or die "Couldn't prepare statement: " . $db->errstr;
	$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
	my @data = $sth->fetchrow_array();
	$sth->finish;
	if ($#data > -1) { return $data[0] + 1; }
	else { return 1; }
}

sub showres {
	open(OUTPUT, $tmpfile);
 
 	if ($nolog eq 0) {
	 	if ($web eq 0) {
	 		print "\nIP address\tPort\tProto\tUser-Agent\n";
			print "==========\t====\t=====\t==========\n";
		}
		else {
	 		print "\nIP address\tPort\tProto\tUser-Agent\tWeb\n";
			print "==========\t====\t=====\t==========\t===\n";
		}
	}

	my @results = <OUTPUT>;
	close (OUTPUT);

	@results = sort(@results);

	foreach(@results) {
		my $line = $_;
		print $line if ($nolog eq 0);
		save($line) if ($withdb eq 1);
	}

	print "\n";
}

sub interrupt {
	if ($abort eq 0) {
		$abort = 1;
		if ($maxthreads > 1) {
			{lock($threads); $threads=$maxthreads;}

			print "Closing threads. Please wait ...\n";
			sleep(2);
		}

		close(OUTPUT);

		showres();
		unlink($tmpfile);
	 
		exit;
	}
	else {
		print "Closing threads. Please wait ...\n\n";
	}
}

sub scan {
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
	send_register($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "tls", $domain) if ($method eq "REGISTER" && ($proto eq "all" || $proto eq "tls"));

	send_invite($contactdomain, $to_ip, $dport, $fromuser, $fromname, $touser, $toname, $csec, "udp", $domain) if ($method eq "INVITE" && ($proto eq "all" || $proto eq "udp"));
	send_invite($contactdomain, $to_ip, $dport, $fromuser, $fromname, $touser, $toname, $csec, "tcp", $domain) if ($method eq "INVITE" && ($proto eq "all" || $proto eq "tcp"));
	send_invite($contactdomain, $to_ip, $dport, $fromuser, $fromname, $touser, $toname, $csec, "tls", $domain) if ($method eq "INVITE" && ($proto eq "all" || $proto eq "tls"));

	send_options($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "udp", $domain) if ($method eq "OPTIONS" && ($proto eq "all" || $proto eq "udp"));
	send_options($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "tcp", $domain) if ($method eq "OPTIONS" && ($proto eq "all" || $proto eq "tcp"));
	send_options($contactdomain, $to_ip, $dport, $fromuser, $fromname, $csec, "tls", $domain) if ($method eq "OPTIONS" && ($proto eq "all" || $proto eq "tls"));
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

		my $data = "";
		my $server = "";
		my $ua = "";
		my $line = "";

		print $sc $msg;

		print "[+] $to_ip:$dport/$proto - Sending REGISTER $fromuser\n" if ($v eq 1);
		print "[+] $to_ip:$dport/$proto - Sending:\n=======\n$msg" if ($vv eq 1);

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
					print "[-] $response\n" if ($v eq 1);
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

			$server = "Unknown" if ($server eq "");
			print OUTPUT "$to_ip\t$dport\t$proto\t$server\n";
			print $tmpfile "$to_ip\t$dport\t$proto\t$server\n";
		}
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

		my $data = "";
		my $server = "";
		my $ua = "";
		my $line = "";

		print $sc $msg;

		print "[+] $to_ip:$dport/$proto - Sending INVITE $fromuser => $touser\n" if ($v eq 1);
		print "[+] $to_ip:$dport/$proto - Sending:\n=======\n$msg" if ($vv eq 1);

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
					print "[-] $response\n" if ($v eq 1);
					print "Receiving:\n=========\n$data" if ($vv eq 1);
					last LOOP if ($server ne "" || $ua ne "");
				}
			}
		}
    
		if ($data ne "" || $server ne "" || $ua ne "") {
			if ($server eq "") {
				$server = $ua;
			}
			else {
				if ($ua ne "") {
					$server .= " - $ua";
				}
			}

			$server = "Unknown" if ($server eq "");
			print OUTPUT "$to_ip\t$dport\t$proto\t$server\n";
			print $tmpfile "$to_ip\t$dport\t$proto\t$server\n";
		}
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

		my $data = "";
		my $server = "";
		my $ua = "";
		my $line = "";

		print $sc $msg;

		print "[+] $to_ip:$dport/$proto - Sending OPTIONS $fromuser\n" if ($v eq 1);
		print "[+] $to_ip:$dport/$proto - Sending:\n=======\n$msg" if ($vv eq 1);

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
					print "[-] $response\n" if ($v eq 1);
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

			$server = "Unknown   " if ($server eq "");
			my $webfound = 0;
			print OUTPUT "$to_ip\t$dport\t$proto\t$server";

			if ($web eq 1) {
				my $sc2 = new IO::Socket::INET->new(PeerPort=>80, Proto=>'tcp', PeerAddr=>$to_ip, Timeout => 10);
				if ($sc2) { $webfound = 1; print OUTPUT "\t80/tcp"; }
				else {
					$sc2 = new IO::Socket::INET->new(PeerPort=>81, Proto=>'tcp', PeerAddr=>$to_ip, Timeout => 10);
					if ($sc2) { $webfound = 1; print OUTPUT "\t81/tcp"; }
					else {
						$sc2 = new IO::Socket::INET->new(PeerPort=>8000, Proto=>'tcp', PeerAddr=>$to_ip, Timeout => 10);
						if ($sc2) { $webfound = 1; print OUTPUT "\t8000/tcp"; }
						else {
							$sc2 = new IO::Socket::INET->new(PeerPort=>8080, Proto=>'tcp', PeerAddr=>$to_ip, Timeout => 10);
							if ($sc2) { $webfound = 1; print OUTPUT "\t8080/tcp"; }
							else {
								$sc2 = new IO::Socket::INET->new(PeerPort=>443, Proto=>'tcp', PeerAddr=>$to_ip, Timeout => 10);
								if ($sc2) { $webfound = 1; print OUTPUT "\t443/tcp"; }
								else { $webfound = 1; print OUTPUT "\t0"; }
							}
						}
					}
				}
			}

			print OUTPUT "\n";
		}
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
SipSCAN - by Pepelux <pepeluxx\@gmail.com>
-------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPscan

Usage: perl $0 -h <host> [options]
 
== Options ==
-m <string>      = Method: REGISTER/INVITE/OPTIONS (default: OPTIONS)
-fu <string>     = From User (by default 100)
-fn <string>     = From Name
-tu <string>     = To User (by default 100)
-tn <string>     = To Name
-cd <string>     = Contact Domain (by default 1.1.1.1)
-d <string>      = Domain (by default: destination IP address)
-r <integer>     = Remote port (default: 5060)
-proto <string>  = Protocol (udp, tcp, tls or all - By default: ALL)
-ua <string>     = Customize the UserAgent
-db              = Save results into database (sippts.db)
                   database path: ${data_path}sippts.db
-th <integer>    = Number of threads (by default 300)
-nolog           = Don't show anything on the console
-noth            = Don't use threads
-web             = Search web control panel
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
-version         = Show version and search for updates

== Examples ==
\$perl $0 -h 192.168.0.1
\tTo search SIP services on 192.168.0.1 port 5060 (using OPTIONS method)
\$perl $0 -h 192.168.0.1,192.168.2.0/24.192.168.3.1-192.168.20.200
\tTo search several ranges
\$perl $0 -h 192.168.0.1 -m INVITE
\tTo search SIP services on 192.168.0.1 port 5060 (using INVITE method)
\$perl $0 -h 192.168.0.0/24 -v -t tcp
\tTo search SIP services on 192.168.0.0 network by TCP connection (using OPTIONS method)
\$perl $0 -h 192.168.0.1-192.168.0.100 -r 5060-5070 -vv
\tTo search SIP services on 192.168.0.100 ports from 5060 to 5070 (using OPTIONS method)
\$perl $0 -h 192.168.0.1 -fn Bob -tn Alice -fu 100 -tu 101 -cd 1.2.3.4 -d sip.mydomain.com -vv

};
 
    exit 1;
}
 
init();
