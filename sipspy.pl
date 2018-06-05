#!/usr/bin/perl
# -=-=-=-=-=-=-=
# SipINVITE v1.2
# -=-=-=-=-=-=-=
#
# Pepelux <pepeluxx@gmail.com>
 
use warnings;
use strict;
#use IO::Socket;
#use IO::Socket::Timeout;
#use NetAddr::IP;
use Getopt::Long;
#use Digest::MD5 qw(md5 md5_hex md5_base64);
use IO::Socket::INET;

my $port = '';	# destination port
my $v = 0;	# verbose mode

sub init() {
	my $socket;

	# check params
	my $result = GetOptions ("p=s" => \$port, "v+" => \$v);

	$port = "5060" if ($port eq "");

	$socket = new IO::Socket::INET (
		LocalPort => $port,
		Proto => 'udp',
	) or die "ERROR in Socket Creation : $!\n";

	while(1) {
		# read operation on the socket
		$socket->recv(my $received_data, 1024);

		#get the peerhost and peerport at which the recent data received.
		my $peer_address = $socket->peerhost();
		my $peer_port = $socket->peerport();
		print "\n[ Conection from: $peer_address:$peer_port ]\n$received_data" if ($v eq 1);
		my $resp = parse_request($received_data, $peer_address, $peer_port);

		#send the data to the client at which the read/write operations done recently.
		print "\n[ Sending response to: $peer_address:$peer_port ]\n$resp" if ($v eq 1);

		if ($resp ne "") {
			my $sc = new IO::Socket::INET->new(PeerPort=>$peer_port, Proto=>'udp', PeerAddr=>$peer_address, Timeout => 10);
			print $sc $resp if ($sc);
			$sc->close();
		}
	}

	$socket->close();
}

sub parse_request() {
	my $data = shift;
	my $host = shift;
	my $port = shift;
	my $line = "";
	my @lines = split(/\n/, $data);
	
	my $resp = "";
	my $method = "";
	my $via = "";
	my $from = "";
	my $to = "";
	my $contact = "";
	my $callid = "";
	my $cseq = "";
	my $digest = "";

	foreach $line (@lines) {
		$method = "OPTIONS" if ($line =~ /^OPTIONS/i);
		$method = "REGISTER" if ($line =~ /^REGISTER/i);
		$method = "INVITE" if ($line =~ /^INVITE/i);
		$method = "ACK" if ($line =~ /^ACK/i);
		$method = "CANCEL" if ($line =~ /^CANCEL/i);
		$method = "UPDATE" if ($line =~ /^UPDATE/i);
		$method = "BYE" if ($line =~ /^BYE/i);
		$via = $line.";received=".$host.";rport=".$port if ($line =~ /^Via/i);
		$from = $line if ($line =~ /^From/i);
		$to = $line if ($line =~ /^To/i);
		$contact = $line if ($line =~ /^Contact/i);
		$callid = $line if ($line =~ /^Call-ID/i);
		$cseq = $line if ($line =~ /^CSeq/i);
		$digest = $line if ($line =~ /digest/i);
	}
	
	print "[=>] $host:$port $method\n" if ($v eq 0);

	if ($method eq "OPTIONS") {
		$resp .= "SIP/2.0 200 OK\n";
	}
	
	if ($method eq "INVITE") {
		$resp .= "SIP/2.0 404 Not Found\n";
	}
	
	if ($method eq "REGISTER") {
		$resp .= "SIP/2.0 401 Unauthorized\n";
		
		if ($digest eq "") {
			$resp .= "WWW-Authenticate: Digest algorithm=MD5, realm=\"asterisk\", nonce=\"405a7bc0\"\n";
			print "     [ Sending digest => WWW-Authenticate: Digest algorithm=MD5, realm=\"asterisk\", nonce=\"405a7bc0\" ]\n";
		}
	}

	$resp .= $via."\n";
	$resp .= $from."\n";
	$resp .= $to."\n";
	$resp .= $callid."\n";
	$resp .= $cseq."\n";
	$resp .= "Server: pplbot\n";
	$resp .= "Content-Length: 0\n\n";
	
	print "     [ Digest response => $digest ]\n" if ($digest ne "");

	return $resp;
}


 
sub help {
    print qq{
SipSPY v1.0 - by Pepelux <pepeluxx\@gmail.com>
--------------

Usage: perl $0 [options]
 
== Options ==
-p  <integer>    = Local port (default: 5060)
-v               = Verbose (trace information)
 
};
 
    exit 1;
}
 
init();
