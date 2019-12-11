#!/usr/bin/perl
# -=-=-=-=
# SipCrack
# -=-=-=-=
#
# Sipcrack is a remote password cracker. Sipcrack can test passwords for
# several users in different IPs and port ranges.
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
use DBI;
use File::Temp qw/ tempfile tempdir /;
use IO::File;

my $useragent = 'pplsip';
 
my @range;
my @results;
my @founds;
 
my $host = '';		# host
my $lport = '';		# local port
my $dport = '';		# destination port
my $contactdomain = ''; # Contact Domain
my $domain = ''; # SIP Domain
my $wordlist = '';	# wordlist
my $v = 0;		# verbose mode
my $vv = 0;		# more verbose
my $exten = '';		# extension
my $prefix = '';	# prefix
my $resume = 0;		# resume
my $abort = 0;
my $proto = '';		# protocol
my $withdb = 0;
my $ver = 0;

my $realm = '';
my $nonce = '';
	
my $to_ip = '';
my $from_ip = '';

my $i;
my $j;
my $k;
my $word = '';
my $wini = '';
my $nhost;
my $pini;
my $pfin;
my $eini;
my $efin;
my $hini = 0;

my $db;
my $usersid;


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
	$usersid = last_id();
}
 
sub init() {
    # check params
    my $result = GetOptions ("h=s" => \$host,
				"cd=s" => \$contactdomain,
				"d=s" => \$domain,
				"e=s" => \$exten,
				"l=s" => \$lport,
				"r=s" => \$dport,
				"w=s" => \$wordlist,
				"p=s" => \$prefix,
				"proto=s" => \$proto,
				"resume+" => \$resume,
				"db+" => \$withdb,
				"ua=s" => \$useragent,
				"version+" => \$ver,
				"v+" => \$v,
				"vv+" => \$vv);

	check_version() if ($ver eq 1);
	help() if (($host eq "" || $wordlist eq "") && $resume eq 0);
	prepare_db() if ($withdb eq 1);

 	$proto = lc($proto);
	$proto = "udp" if ($proto ne "tcp");

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
			push @range, $ip->addr;
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
		$exten = "100-300" if ($exten eq "");
		$contactdomain = "1.1.1.1" if ($contactdomain eq "");

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
 	
	my @arrow = ("|", "/", "-", "\\");
	my $cont = 0;

	while(<WL>) {
		chomp;
		
		$word = $_;
		
		$analize = 1 if ($wini eq '' || $wini eq $word);
		
		if ($analize eq 1) {
			for ($i = $hini; $i <= $nhost; $i++) {
				for ($j = $pini; $j <= $pfin; $j++) {
					for ($k = $eini; $k <= $efin; $k++) {
						while (1) {
							last unless defined($range[$i]);
							$from_ip = $range[$i] if ($from_ip eq "");
							my $sipdomain = $domain;
							$sipdomain = $range[$i] if ($domain eq "");
							my $user = $prefix.$k;

							if ( !grep( /^$user$/, @founds ) ) {
								print "\r[".$arrow[$cont]."] Testing ".$range[$i].":$j with $user/$word ..." if ($v ne 1 && $vv ne 1);
								scan($range[$i], $lport, $j, $contactdomain, $user, $proto, $sipdomain, $word);
							}

							$cont++;
							$cont = 0 if ($cont > 3);

							last;
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
 
	print "\nIP address\tPort\tProto\tExten\tPass\n";
	print "==========\t====\t=====\t=====\t====\n";

	my @results = <OUTPUT>;
	close (OUTPUT);

	unlink($tmpfile);

	@results = sort(@results);

	foreach(@results) {
		my $line = $_;
		print $line;
		save($line) if ($withdb eq 1);
	}

	print "\n";

	exit;
}

sub last_id {
	my $sth = $db->prepare('SELECT id FROM users ORDER BY id DESC LIMIT 1') or die "Couldn't prepare statement: " . $db->errstr;
	$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
	my @data = $sth->fetchrow_array();
	$sth->finish;
	if ($#data > -1) { return $data[0] + 1; }
	else { return 1; }
}

sub interrupt {
	if ($abort eq 0) {
		$abort = 1;
		my $i2 = $i;
		my $j2 = $j;
		my $k2 = $k;

		close (WL);
		close(OUTPUT);

		open(OUTPUT, $tmpfile);

		print "\nIP address\tPort\tProto\tExten\tPass\n";
		print "==========\t====\t=====\t=====\t====\n";

		my @results = <OUTPUT>;
		close (OUTPUT);

		unlink($tmpfile);

		@results = sort(@results);

		foreach(@results) {
			my $line = $_;
			print $line;
			save($line) if ($withdb eq 1);
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
}

sub save {
	my $line = shift;

		my @lines = split (/\t/, $line);
		my $sth = $db->prepare("SELECT id FROM users WHERE host='".$lines[0]."' AND port=".$lines[1]." AND user='".$lines[3]."'") or die "Couldn't prepare statement: " . $db->errstr;
		$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;
		my @data = $sth->fetchrow_array();
		my $sql;
		$sth->finish;
		if ($#data < 0) {
			$sql = "INSERT INTO users (id, host, port, proto, user, pass) VALUES ($usersid, '".$lines[0]."', ".$lines[1].", '".$lines[2]."', '".$lines[3]."', '".$lines[4]."')";
			$db->do($sql);
			$usersid = $db->func('last_insert_rowid') + 1;
		}
		else {
			$sql = "UPDATE users SET proto='".$lines[2]."', pass='".$lines[4]."' WHERE host='".$lines[0]."' AND port=".$lines[1]." AND user='".$lines[3]."'";
			$db->do($sql);
		}
}

sub scan {
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $contactdomain = shift;
	my $user = shift;
	my $proto = shift;
	my $domain = shift;
	my $pass = shift;

	my $callid = &generate_random_string(32, 1);
	my $cseq = 1;
	
	send_register($contactdomain, $to_ip, $lport, $dport, $user, "", $proto, $domain, "", $callid);

	my $uri = "sip:$domain";
	my $a = md5_hex($user.':'.$realm.':'.$pass);
	my $b = md5_hex('REGISTER:'.$uri);
	my $r = md5_hex($a.':'.$nonce.':'.$b);
	my $digest = "username=\"$user\",realm=\"$realm\",nonce=\"$nonce\",uri=\"$uri\",response=\"$r\",algorithm=MD5";
	$cseq = 2;
	my $res = send_register($contactdomain, $to_ip, $lport, $dport, $user, $digest, $proto, $domain, $pass, $callid);

	push @founds, $user if ($res =~ /^200/);
}
 
# Send REGISTER message
sub send_register {
	my $contactdomain = shift;
	my $to_ip = shift;
	my $lport = shift;
	my $dport = shift;
	my $user = shift;
	my $digest = shift;
	my $proto = shift;
	my $domain = shift;
	my $pass = shift;
	my $callid = shift;
	my $response = "";

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>$proto, PeerAddr=>$to_ip, Timeout => 10);

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(0.5);
		$sc->enable_timeout;

		my $branch = &generate_random_string(71, 0);
	
		my $msg = "REGISTER sip:".$user."@".$domain." SIP/2.0\r\n";
		$msg .= "Via: SIP/2.0/".uc($proto)." $contactdomain:$lport;branch=$branch\r\n";
		$msg .= "From: <sip:".$user."@".$domain.">;tag=0c26cd11\r\n";
		$msg .= "To: <sip:".$user."@".$domain.">\r\n";
		$msg .= "Contact: <sip:".$user."@".$contactdomain.":$lport;transport=$proto>\r\n";
		$msg .= "Authorization: Digest $digest\r\n" if ($digest ne "");
		$msg .= "Call-ID: ".$callid."\r\n";
		$msg .= "CSeq: 1 REGISTER\r\n";
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

		print "[+] $to_ip/$proto - Sending REGISTER $user (trying pass: $pass)\n" if ($pass ne "" && $v eq 1);
		print "[+] $to_ip/$proto - Sending REGISTER $user\n" if ($pass eq "" && $v eq 1);
		print "[+] $to_ip/$proto - Sending:\n=======\n$msg" if ($vv eq 1);

		use Errno qw(ETIMEDOUT EWOULDBLOCK);
		
		LOOP: {
			my $m = 1;
			my $c = 1;

			while (<$sc>) {
				if ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ) {
					return "";
				}

				$line = $_;
				if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
					$line =~ /^SIP\/2.0\s(.+)\r\n/;

					if ($1) { $response = $1; }
				}

				if ($line =~ /^CSeq/i) {
					$line =~ /^Cseq:\s[0-9]+\s(.+)\r\n/i;
					$m = 0 if ($1 !~ /REGISTER/);
				}


				if ($line =~ /^Call-ID/i) {
					$line =~ /^Call-ID:\s(.+)\r\n/i;
				
					$c = 0 if ($callid ne $1);
				}

				if ($line =~ /^WWW-Authenticate:/ || $line =~ /^Proxy-Authenticate:/) {
					$line =~ /.*realm=\"([a-zA-Z0-9\.\_\-]*)\".*/;
					$realm = $1 if ($1);
					$line =~ /.*nonce=\"([a-zA-Z0-9\/\=\.\_\-\,]*)\".*/;
					$nonce = $1 if ($1);
				}
 
				$data .= $line;
 
				if ($line =~ /^\r\n/) {
					print "[-] $response\n" if ($v eq 1);
					print "Receiving:\n=========\n$data" if ($vv eq 1);

					last LOOP if ($response !~ /^1/ && $m eq 1 && $c eq 1);

					$response = "" if ($response =~ /^1/ && $m eq 1 && $c eq 1);
				}
			}
		}

		if ($response =~ "^200") {
			print OUTPUT "$to_ip\t$dport\t$proto\t$user\t$pass\n";
			print "\nFound match: $to_ip:$dport/$proto - User: $user - Pass: $pass\n";
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
SipCRACK - by Pepelux <pepeluxx\@gmail.com>
--------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPcrack

Usage: perl $0 -h <host> -w wordlist [options]
 
== Options ==
-e  <string>     = Extension (default from 100 to 300)
-cd <string>     = Contact Domain (by default 1.1.1.1)
-d  <string>     = Domain (by default: destination IP address)
-l  <integer>    = Local port (default: 5070)
-r  <integer>    = Remote port (default: 5060)
-p  <string>     = Prefix (for extensions)
-proto <string>  = Protocol (udp or tcp - By default: udp)
-ua <string>     = Customize the UserAgent
-resume          = Resume last session
-db              = Save results into database (sippts.db)
                   database path: ${data_path}sippts.db
-v               = Verbose (trace information)
-vv              = More verbose (more detailed trace)
-version         = Show version and search for updates
 
== Examples ==
\$perl $0 -h 192.168.0.1 -w wordlist
\tTry to crack extensions from 100 to 1000 on 192.168.0.1 port 5060
\$perl $0 -h 192.168.0.0/24 -e 100-200 -p user -w wordlist -v
\tTry to crack extensions from user100 to user200 on 192.168.0.0 network

};
 
    exit 1;
}
 
init();
