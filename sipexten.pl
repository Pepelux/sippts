#!/usr/bin/perl
# -=-=-=-=
# SipExten
# -=-=-=-=
#
# Sipexten identifies extensions on a SIP server. Sipexten can check large
# network and port ranges.
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
use Digest::MD5;
use DBI;
use File::Temp qw(tempfile);

my $useragent = 'pplsip';

my @range;
my @results;
 
my $host = ''; # host
my $lport = '5070';	# local port
my $dport = '5060';	# destination port
my $fromuser = '100'; # From User
my $fromname = '100'; # From Name
my $contactdomain = '1.1.1.1'; # Contact Domain
my $domain = ''; # SIP Domain
my $v = 0; # verbose mode
my $vv = 0; # more verbose
my $method = 'REGISTER'; # method to use (INVITE, REGISTER, OPTIONS)
my $nolog = 0;
my $exten = '100-300'; # extension
my $prefix = ''; # prefix
my $proto = '';	# protocol
my $withdb = 0;
my $ver = 0;

my $to_ip = '';
my $from_ip = '';

my $alwaysok = '';
my $server = '';

my $db;
my $extensid;
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
	$extensid = last_id("extens");
	$hostsid = last_id("hosts");
}

sub init() {
    my $pini;
    my $pfin;
    my $eini;
    my $efin;
 
    # check params
    my $result = GetOptions ("h=s" => \$host,
				"m=s" => \$method,
				"fu=s" => \$fromuser,
				"fn=s" => \$fromname,
				"fu=s" => \$fromuser,
				"cd=s" => \$contactdomain,
				"d=s" => \$domain,
				"e=s" => \$exten,
				"l=s" => \$lport,
				"r=s" => \$dport,
				"proto=s" => \$proto,
				"p=s" => \$prefix,
				"db+" => \$withdb,
				"nolog+" => \$nolog,
				"ua=s" => \$useragent,
				"version+" => \$ver,
				"v+" => \$v,
				"vv+" => \$vv);
 
	check_version() if ($ver eq 1);
	help() if ($host eq "");
	prepare_db() if ($withdb eq 1);

	$proto = lc($proto);
	$proto = "all" if ($proto ne "tcp" && $proto ne "udp");
	$method = uc($method);

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

	if ($exten =~ /\-/) {
		$exten =~ /([0-9]*)-([0-9]*)/;
		$eini = $1;
		$efin = $2;
	}
	else {
		$eini = $exten;
		$efin = $exten;
	}

	my $nhost = @range;
	my $p = $proto;
	my @arrow = ("|", "/", "-", "\\");
	my $cont = 0;

	for (my $i = 0; $i < $nhost; $i++) {
		for (my $j = $pini; $j <= $pfin; $j++) {
			##### Executed only one time
			# Get User-agent/server from an OPTIONS message
			my $user = $prefix."1";
			my $sipdomain = $domain;
			$sipdomain = $range[$i] if ($domain eq "");

			if ($server eq "") {
				$p = "udp" if ($proto eq "all");
				$from_ip = $range[$i] if ($from_ip eq "");
				$server = send_options($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $fromuser, 1, $p, $sipdomain);
				send_options($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $fromuser, 1, "tcp", $sipdomain) if (($proto eq "all" && $server eq "") || $proto eq "tcp");
			}
			# Some systems always response 'Ok'. On this case only get the error responses
			if ($alwaysok eq "") {
				my $resinvite = send_invite($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, "123456789", 1, $p, $sipdomain);
				if ($resinvite =~ "^4" || $resinvite eq "") {
					$alwaysok = "no";
				} else {
					$alwaysok = "yes";
				}
			}
			#####
				
			for (my $k = $eini; $k <= $efin; $k++) {
				$user = $prefix.$k;

				while (1) {
					my $touser = $prefix.$k;
					last unless defined($range[$i]);
					my $csec = 1;
					$from_ip = $range[$i] if ($from_ip eq "");
					my $sipdomain = $domain;
					$sipdomain = $range[$i] if ($domain eq "");
					print "\r[".$arrow[$cont]."] Scanning ".$range[$i].":$j with exten $user ...";
					scan($range[$i], $lport, $j, $contactdomain, $fromuser, $fromname, $touser, $csec, $proto, $sipdomain);
					$cont++;
					$cont = 0 if ($cont > 3);

					last;
				}
			}
		}
	}

	sleep(1);

	close(OUTPUT);

	showres();
	unlink($tmpfile);

	exit;
}

sub showres {
	open(OUTPUT, $tmpfile);
 
 	if ($nolog eq 0) {
		print "\nIP address\tPort\tProto\tExtension\tAuthentication\t\tUser-Agent\n";
		print "==========\t====\t=====\t=========\t==============\t\t==========\n";
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

sub last_id {
	my $cdb = shift;

	my $sth = $db->prepare("SELECT id FROM $cdb ORDER BY id DESC LIMIT 1") or die "Couldn't prepare statement: " . $db->errstr;
	$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
	my @data = $sth->fetchrow_array();
	$sth->finish;
	if ($#data > -1) { return $data[0] + 1; }
	else { return 1; }
}

sub interrupt {
	close(OUTPUT);

	showres();
	unlink($tmpfile);

	exit;
}

sub save {
	my $line = shift;

		my @lines = split (/\t/, $line);
		my $sth = $db->prepare("SELECT id FROM hosts WHERE host='".$lines[0]."'") or die "Couldn't prepare statement: " . $db->errstr;
		$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
		my @data = $sth->fetchrow_array();
		my $sql;
		$sth->finish;
		if ($#data < 0) {
			$sql = "INSERT INTO hosts (id, host, port, proto, useragent) VALUES ($hostsid, '".$lines[0]."', ".$lines[1].", '".$lines[2]."', '".$lines[6]."')";
			$db->do($sql);
			$hostsid = $db->func('last_insert_rowid') + 1;
		}

		$sth = $db->prepare("SELECT id FROM extens WHERE host='".$lines[0]."' AND exten='".$lines[3]."'") or die "Couldn't prepare statement: " . $db->errstr;
		$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
		@data = $sth->fetchrow_array();
		$sth->finish;
		if ($#data < 0) {
			$sql = "INSERT INTO extens (id, host, port, proto, exten, auth) VALUES ($extensid, '".$lines[0]."', ".$lines[1].", '".$lines[2]."', '".$lines[3]."', '".$lines[5]."')";
			$db->do($sql);
			$extensid = $db->func('last_insert_rowid') + 1;
		}
		else {
			$sql = "UPDATE extens SET port=".$lines[1].", proto='".$lines[2]."', auth='".$lines[5]."' WHERE host='".$lines[0]."' AND exten='".$lines[3]."'";
			$db->do($sql);
		}
}

sub scan {
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $contactdomain = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $touser = shift;
	my $csec = shift;
	my $proto = shift;
	my $domain = shift;

	my $p = $proto;
	my $r = '';

	$p = "udp" if ($proto eq "all");
	$r = send_register($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $touser, $csec, $p, $domain) if ($method eq "REGISTER");
	send_register($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $touser, $csec, "tcp", $domain) if ($method eq "REGISTER" && ($proto eq "all" && $r eq "")) || $proto eq "tcp";
	$r = send_invite($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $touser, $csec, $p, $domain) if ($method eq "INVITE");
	send_invite($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $touser, $csec, "tcp", $domain) if ($method eq "INVITE" && ($proto eq "all" && $r eq "") || $proto eq "tcp");
	$r = send_options($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $touser, $csec, $p, $domain) if ($method eq "OPTIONS");
	send_options($contactdomain, $to_ip, $lport, $dport, $fromuser, $fromname, $touser, $csec, "tcp", $domain) if ($method eq "OPTIONS" && ($proto eq "all" && $r eq "") || $proto eq "tcp");
}
 
# Send INVITE message
sub send_invite {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $touser = shift;
	my $cseq = shift;
	my $proto = shift;
	my $domain = shift;
	my $response = "";
	my $server = "";

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 10);

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;
		$lport = $sc->sockport();

		my $branch = &generate_random_string(71, 0);
		my $callid = &generate_random_string(32, 1);
	
		my $msg = "INVITE sip:".$touser."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: $fromname <sip:".$fromuser."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: <sip:".$touser."@".$domain.">\r\n";
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
					print "[-] $response\n" if ($v eq 1);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					if ($response =~ "^200") {
						if ($server eq "") {
							$server = $ua;
						}
						else {
							if ($ua ne "") {
								$server .= " - $ua";
							}
						}

						$server = "Unknown" if ($server eq "");
					}

					if ($touser ne "123456789") {
						if ($response =~ "^1") {
							if ($alwaysok eq "no") {
								print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tNo auth required\t$server\n";
								print "\rFound match: $to_ip:$dport/$proto - User: $touser - No auth required\n";
							}
						}
						else {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tRequire authentication\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - Require authentication\n";
						}
					}
					last LOOP;
				}
			}
		}
    	}

	return $response;
}

# Send REGISTER message
sub send_register {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $touser = shift;
	my $cseq = shift;
	my $proto = shift;
	my $domain = shift;
	my $response = "";
	my $server = "";

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 10);

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;
		$lport = $sc->sockport();

		my $branch = &generate_random_string(71, 0);
		my $callid = &generate_random_string(32, 1);
	
		my $msg = "REGISTER sip:".$touser."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: $fromname <sip:".$fromuser."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: <sip:".$touser."@".$domain.">\r\n";
		$msg .= "Contact: <sip:".$fromuser."@".$contactdomain.":$lport;transport=$proto>\r\n";
		$msg .= "Call-ID: ".$callid."\r\n";
		$msg .= "CSeq: $cseq REGISTER\r\n";
		$msg .= "User-Agent: $useragent\r\n";
		$msg .= "Max-Forwards: 70\r\n";
		$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
		$msg .= "Expires: 10\r\n";
		$msg .= "Content-Length: 0\r\n\r\n";

		my $data = "";
		my $ua = "";
		my $line = "";

		print $sc $msg;

		print "[+] $to_ip:$dport/$proto - Sending INVITE $touser\n" if ($v eq 1);
		print "[+] $to_ip:$dport/$proto - Sending:\n=======\n$msg" if ($vv eq 1);

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
	
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
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
					print "[-] $response\n" if ($v eq 1);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					if ($response =~ "^200") {
						if ($server eq "") {
							$server = $ua;
						}
						else {
							if ($ua ne "") {
								$server .= " - $ua";
							}
						}

						$server = "Unknown" if ($server eq "");
					}

					if ($response =~ "^1" || $response =~ "^2") {
						if ($alwaysok eq "no") {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tNo auth required\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - No auth required\n";
						}
					}
					else {
						if ($response =~ "^401" || $response =~ "^407") {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tRequire authentication\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - Require authentication\n";
						}
						if ($response =~ "^403") {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tIP filtered\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - IP filtered\n";
						}
					}
					last LOOP;
				}
			}
		}
    	}

	return $response;
}

# Send OPTIONS message
sub send_options {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $fromuser = shift;
	my $fromname = shift;
	my $touser = shift;
	my $cseq = shift;
	my $proto = shift;
	my $domain = shift;
	my $response = "";
	my $server = "";

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 10);

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;
		$lport = $sc->sockport();

		my $branch = &generate_random_string(71, 0);
		my $callid = &generate_random_string(32, 1);
	
		my $msg = "OPTIONS sip:".$touser."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: $fromname <sip:".$fromuser."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: <sip:".$touser."@".$domain.">\r\n";
		$msg .= "Contact: <sip:".$fromuser."@".$contactdomain.":$lport;transport=$proto>\r\n";
		$msg .= "Call-ID: $callid\r\n";
		$msg .= "CSeq: $cseq OPTIONS\r\n";
		$msg .= "User-Agent: $useragent\r\n";
		$msg .= "Max-Forwards: 70\r\n";
		$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
		$msg .= "Content-Length: 0\r\n\r\n";

		my $data = "";
		my $ua = "";
		my $line = "";

		print $sc $msg;

		print "[+] $to_ip:$dport/$proto - Sending OPTIONS $touser\n" if ($v eq 1);
		print "[+] $to_ip:$dport/$proto - Sending:\n=======\n$msg" if ($vv eq 1);

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
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
					print "[-] $response\n" if ($v eq 1);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					if ($response =~ "^200") {
						if ($server eq "") {
							$server = $ua;
						}
						else {
							if ($ua ne "") {
								$server .= " - $ua";
							}
						}

						$server = "Unknown" if ($server eq "");
					}

					if ($response =~ "^1" || $response =~ "^2") {
						if ($alwaysok eq "no") {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tNo auth required\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - No auth required\n";
						}
					}
					else {
						if ($response =~ "^401" || $response =~ "^407") {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tRequire authentication\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - Require authentication\n";
						}
						if ($response =~ "^403") {
							print OUTPUT "$to_ip\t$dport\t$proto\t$touser\t\tIP filtered\t$server\n";
							print "\rFound match: $to_ip:$dport/$proto - User: $touser - IP filtered\n";
						}
					}
					last LOOP;
				}
			}
		}
	}
	
	return $server;
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
SipEXTEN - by Pepelux <pepeluxx\@gmail.com>
--------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPexten

Usage: perl $0 -h <host> [options]
 
== Options ==
-m  <string>     = Method: REGISTER/INVITE/OPTIONS (default: REGISTER)
-e  <string>     = Extensions (default 100-300)
-fu  <string>    = From User (by default 100)
-fn  <string>    = From Name
-cd <string>     = Contact Domain (by default 1.1.1.1)
-d  <string>     = Domain (by default: destination IP address)
-l  <integer>    = Local port (default: 5070)
-r  <integer>    = Remote port (default: 5060)
-p  <string>     = Prefix (for extensions)
-proto <string>  = Protocol (udp, tcp or all (both of them) - By default: ALL)
-ua <string>     = Customize the UserAgent
-db              = Save results into database (sippts.db)
                   database path: ${data_path}sippts.db
-nolog           = Don't show anything on the console
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
-version         = Show version and search for updates
 
== Examples ==
\$perl $0 -h 192.168.0.1 -e 100-200 -m REGISTER -v
\tTo check extensions range from 100 to 200 using REGISTER method (with verbose mode)
\$perl $0 -h 192.168.0.0/24 -e 100-2000 -r 5060-5080
\tSearch extensions from 100 to 2000 on a network range with destination port between 5060 and 5080
\$perl $0 -h 192.168.0.0/24 -e 100-200 -db
\tSave all operations into a database
\$perl $0 -h 192.168.0.0/24 -e 100-200 -ua myUserAgent
\tCustomize User-Agent
\$perl $0 -h 192.168.0.100 -e 100-101 -p user
\tTo check extensions user100 and user101 in 192.168.0.100

};
 
    exit 1;
}
 
init();
