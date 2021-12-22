#!/usr/bin/perl
# -=-=-=-=
# SipSNIFF
# -=-=-=-=
#
# Sipsniff is a very simple sniffer for SIP protocol that allows us to filter
# by SIP method type.
#
# based on remote-exploit.org perl sniffer script: http://www.remote-exploit.org/downloads/simple-perl-sniffer.pl.gz
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

use strict;
use Net::Pcap;
use Getopt::Long;
use String::HexConvert ':all';
use MIME::Base64;
use IO::Socket;

# Do no buffering - flushing output directly
$|=1;
#declaration of functions
sub f_probe_pcapinit;
sub f_probe_read80211b_func;
sub f_probe_ctrl_c;

# Declarations of global variables
my $g_pcap_err = '';
my $interface = '';
my $dport = '5060';
my $u = 0;
my $method = '';
my $g_cap_descrip;
my $ver = 0;


# Trapping Signal "INT" like ctrl+c for cleanup first.
$SIG{INT} = \&f_probe_ctrl_c; 

sub init() {
	# check params
	my $result = GetOptions ("i=s" => \$interface,
				"m=s" => \$method,
				"p=s" => \$dport,
				"version+" => \$ver,
				"u+" => \$u);

	check_version() if ($ver eq 1);
	help() if ($interface eq "");

	f_probe_pcapinit;
}


sub f_probe_pcapinit{
	if ($g_cap_descrip = Net::Pcap::open_live($interface,2000,0,1000,\$g_pcap_err)) {
		# Initiate endless packet gathering.
		Net::Pcap::loop($g_cap_descrip, -1, \&f_probe_read80211b_func , '' );
	}
	else {
		print "\nCould not initiating the open_live command on $interface from the pcap.\nThe following error where reported: $g_pcap_err\n";
		exit;
	}
};

sub f_probe_read80211b_func {
	my($data, $header, $packet) = @_;
	$data = unpack ('H*',$packet);
	
	if (proto($data) eq "17") {
		my $ipsrc = ipsrc($data);
		my $ipdst = ipdst($data);
		my $portsrc = portsrc($data);
		my $portdst = portdst($data);
		
		if ($portdst eq $dport || $portsrc eq $dport) {		
			my $cleandata = substr($data, 84);
        	my $msg = hex_to_ascii($cleandata);
        	$msg = clear($msg);
			my ($method) = $msg =~ m/^([\w.\/]+)\s/;
			
			if (defined($method) && $method ne "") {
				if ($u eq 0) {
					print "[+] $ipsrc:$portsrc => $ipdst:$portdst\n";
					print $msg."\n\n";
				}
				else {
					my $auth = auth($msg);
					print $auth."\n" if ($auth ne "");
				}
			}
		}
	}
};

sub clear {
	my $msg = shift;

	while ( $msg ne "" && $msg !~ /^[A-Z]/ ) {
		$msg = substr( $msg, 1 );
	}

	return $msg;
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
 
sub ipsrc {
	my $data = shift;
	$data = substr($data, 52, 8);
	my $v1 = hex(substr($data, 0 , 2));
	my $v2 = hex(substr($data, 2 , 2));
	my $v3 = hex(substr($data, 4 , 2));
	my $v4 = hex(substr($data, 6 , 2));
	
	return $v1.".".$v2.".".$v3.".".$v4;
};

sub ipdst {
	my $data = shift;
	$data = substr($data, 60, 8);
	my $v1 = hex(substr($data, 0 , 2));
	my $v2 = hex(substr($data, 2 , 2));
	my $v3 = hex(substr($data, 4 , 2));
	my $v4 = hex(substr($data, 6 , 2));
	
	return $v1.".".$v2.".".$v3.".".$v4;
};

sub portsrc {
	my $data = shift;
	$data = substr($data, 68, 4);

	return hex($data);
};

sub portdst {
	my $data = shift;
	$data = substr($data, 72, 4);
	
	return hex($data);
};

sub proto {
	my $data = shift;
	$data = substr($data, 46, 2);
	
	return hex($data);
};

sub method {
	my $data = shift;
	$data = hex_to_ascii($data);
	
	$data =~ /([A-Z]+)\s/;
	my $method = $1;

	return $method;
};

sub auth {
	my $data = shift;
	$data = hex_to_ascii($data);
	my $data1 = lc($data);
	my $pos1 = index($data1, "authorization")+15;
	return "" if ($pos1 < 15);
	
	my $pos2 = index($data1, "\n", $pos1);
	my $auth = substr($data, $pos1, $pos2-$pos1);

	return $auth;
};

sub f_probe_ctrl_c {
	# Checks if there is a open pcap handle and closes it first.
	if ($g_cap_descrip) {
		Net::Pcap::close ($g_cap_descrip);
		print "\nClosed the pcap allready, the program exits now.\n";
	}
};

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
SipSNIFF - by Pepelux <pepeluxx\@gmail.com>
--------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPsniff

Usage: sudo perl -i <interface> $0 [options]
 
== Options ==
-i  <string>     = Interface (ex: eth0)
-p  <integer>    = Port (default: 5060)
-m  <string>     = Filter method (ex: INVITE, REGISTER)
-u               = Filter users
-version         = Show version and search for updates
 
== Examples ==
\$sudo perl $0 -i eth0
\$sudo perl $0 -i eth0 -m INVITE

};
 
	exit 1;
}

init();
