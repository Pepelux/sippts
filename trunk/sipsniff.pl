#!/usr/bin/perl
# -=-=-=-=-=-=
# RtpScan v1.2
# -=-=-=-=-=-=
#
# Pepelux <pepeluxx@gmail.com>
#
# based on remote-exploit.org perl sniffer script: http://www.remote-exploit.org/downloads/simple-perl-sniffer.pl.gz

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
my $dport = '';
my $u = 0;
my $method = '';
my $g_cap_descrip;

my $useragent = 'sipptk';

# Trapping Signal "INT" like ctrl+c for cleanup first.
$SIG{INT} = \&f_probe_ctrl_c; 

sub init() {
	# check params
	my $result = GetOptions ("i=s" => \$interface,
				"m=s" => \$method,
				"p=s" => \$dport,
				"u+" => \$u);

	help() if ($interface eq "");
	$dport = "5060" if ($dport eq "");

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
			my $m = method($cleandata);
			
			if ($method eq "" || $method eq $m) {
				if ($u eq 0) {
					print "[+] $ipsrc:$portsrc => $ipdst:$portdst\n";
					print hex_to_ascii($cleandata)."\n\n";
				}
				else {
					my $auth = auth($cleandata);
					print $auth."\n" if ($auth ne "");
				}
			}
		}
	}
};

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

sub help {
	print qq{
SipSNIFF v1.2 - by Pepelux <pepeluxx\@gmail.com>
-------------

Usage: sudo perl -i <interface> $0 [options]
 
== Options ==
-i  <string>     = Interface (ex: eth0)
-p  <integer>    = Port (default: 5060)
-m  <string>     = Filter method (ex: INVITE, REGISTER)
-u               = Filter users
 
== Examples ==
\$sudo perl $0 -i eth0
\$sudo perl $0 -i eth0 -m INVITE

};
 
	exit 1;
}

init();
