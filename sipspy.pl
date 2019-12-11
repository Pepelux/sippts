#!/usr/bin/perl
# -=-=-=
# SipSPY
# -=-=-=
#
# Sipspy is a fake SIP server that listens on port 5060/UDP and responds to
# REGISTER message authentication requests.
# The purpose of sipspy is to obtain the digest authentication response from
# a device that thinks it is connecting to a PBX server:
#
# Device                                   Fake SIP Server
#        ---> REGISTER (with no auth) ---> 
#        <--- 401 Unauthorized        <---
#        ---> REGISTER (with auth)    ---> 
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
#use IO::Socket;
#use IO::Socket::Timeout;
#use NetAddr::IP;
use Getopt::Long;
#use Digest::MD5 qw(md5 md5_hex md5_base64);
use IO::Socket::INET;

my $port = '5060'; # destination port
my $v = 0; # verbose mode
my $h = 0; # help
my $ver = 0;



sub init() {
	my $socket;

	# check params
	my $result = GetOptions ("p=s" => \$port, 
				"v+" => \$v, 
				"version+" => \$ver,
				"h+" => \$h);

	check_version() if ($ver eq 1);
	help() if ($h eq 1);

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
		$via = $line if ($line =~ /^Via/i);
		$from = $line if ($line =~ /^From/i);
		$to = $line if ($line =~ /^To/i);
		$contact = $line if ($line =~ /^Contact/i);
		$callid = $line if ($line =~ /^Call-ID/i);
		$cseq = $line if ($line =~ /^CSeq/i);
		$digest = $line if ($line =~ /digest/i);
	}

	$via =~ s/\r//g;
	$via =~ s/\n//g;
	$via = $via.";received=".$host.";rport=".$port if ($via ne '');
	
	print "[=>] $host:$port $method\r\n" if ($v eq 0);

	if ($method eq "OPTIONS") {
		$resp .= "SIP/2.0 200 OK\r\n";
	}
	
	if ($method eq "INVITE") {
		$resp .= "SIP/2.0 404 Not Found\r\n";
	}
	
	if ($method eq "REGISTER") {
		$resp .= "SIP/2.0 401 Unauthorized\r\n";
		
		if ($digest eq "") {
			$resp .= "WWW-Authenticate: Digest algorithm=MD5, realm=\"asterisk\", nonce=\"405a7bc0\"\r\n";
			print "     [ Sending digest => WWW-Authenticate: Digest algorithm=MD5, realm=\"asterisk\", nonce=\"405a7bc0\" ]\r\n";
		}
	}

	$resp .= $via."\r\n";
	$resp .= $from."\r\n";
	$resp .= $to."\r\n";
	$resp .= $callid."\r\n";
	$resp .= $cseq."\r\n";
	$resp .= "Server: pplbot\r\n";
	$resp .= "Content-Length: 0\r\n\r\n";
	
	print "     [ Digest response => $digest ]\n" if ($digest ne "");

	return $resp;
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
SipSPY - by Pepelux <pepeluxx\@gmail.com>
------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPspy

Usage: perl $0 [options]
 
== Options ==
-h               = This help
-p  <integer>    = Local port (default: 5060)
-v               = Verbose (trace information)
-version         = Show version and search for updates
 
};
 
    exit 1;
}
 
init();
