#!/usr/bin/perl
# -=-=-=-=-=-=-
# SipBYE v1.2.1
# -=-=-=-=-=-=-
#
# Pepelux <pepeluxx@gmail.com>
 
use warnings;
use strict;
use IO::Socket;
use NetAddr::IP;
use Getopt::Long;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use MIME::Base64;

my $useragent = 'pplsip';
my $version = '1.2.1';

my $host = '';	# host
my $lport = '';	# local port
my $dport = '';	# destination port
my $v = 0;	# verbose mode
my $msg = '';	# auth user

my $to_ip = '';
 
sub init() {
	# check params
	my $result = GetOptions ("h=s" => \$host,
				"d=s" => \$dport,
				"l=s" => \$lport,
				"b=s" => \$msg,
				"ua=s" => \$useragent,
				"v+" => \$v);

	help() if ($host eq "" || $lport eq "" || $msg eq "");
	check_version();

#	$to_ip = inet_ntoa(inet_aton($host));
	$dport = "5060" if ($dport eq "");

	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 10);
#	my $lport = $sc->sockport();

	# send BYE
#	my $csec = 1;
	send_bye($host, $dport, $lport, $msg);

	exit;
}


# Send BYE message
sub send_bye {
	my $to_ip = shift;
	my $dport = shift;
	my $lport = shift;
	my $msg = shift;
	
	my $branch = &generate_random_string(71, 0);
	$msg = decode_base64($msg);
	my $sc = new IO::Socket::INET->new(PeerPort=>$dport, LocalPort=>$lport, Proto=>'udp', PeerAddr=>$to_ip, Timeout => 10);

	print $sc $msg;

	if ($v eq 0) { print "[+] Sending BYE\n"; }
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
SipBYE v1.2.1 - by Pepelux <pepeluxx\@gmail.com>
-------------

Usage: perl $0 -h <host> -p <port> -c <callid> [options]
 
== Options ==
-p  <integer>    = Remote port
-c  <string>     = Call-ID
-ua <string>     = Customize the UserAgent
-v               = Verbose (trace information)
 
== Examples ==
\$perl $0 -h 192.168.0.1 -p 5060
 
};
 
    exit 1;
}
 
init();
