#!/usr/bin/perl
# -=-=-=-=-=-=-=
# SipReport v1.2
# -=-=-=-=-=-=-=
#
# Pepelux <pepeluxx@gmail.com>
 
use warnings;
use strict;
use Getopt::Long;
use DBI;

my $host = '';		# host

my $database = "sippts.db";

unless (-e $database) {
	die("Database $database not found\n\n");
}
	
my $db = DBI->connect("dbi:SQLite:dbname=$database","","") or die $DBI::errstr;

sub init() {
    # check params
    my $result = GetOptions ("h=s" => \$host);
 
	help() if ($host eq "");
	
	my @data = split(/\./, $host);
	my $search = "";
	if ($data[3] eq "0") { $search = "host LIKE '".$data[0].".".$data[1].".".$data[2].".%'"; }
	else { $search = "host='$host'"; }
 
	my $sth = $db->prepare("SELECT host, port, proto, useragent FROM hosts WHERE $search ORDER BY host ASC") or die "Couldn't prepare statement: " . $db->errstr;
	$sth->execute() or die "Couldn't execute statement: " . $sth->errstr;

	while (@data = $sth->fetchrow_array()) {
		my $host = $data[0];
		$host =~ s/\n//g;
		my $port = $data[1];
		$port =~ s/\n//g;
		my $proto = $data[2];
		$proto =~ s/\n//g;
		my $ua = $data[3];
		$ua =~ s/\n//g;
		print "[+] $host:$port/$proto \t- UserAgent: $ua\n";

		my $sth2 = $db->prepare("SELECT exten, auth FROM extens WHERE $search ORDER BY host ASC") or die "Couldn't prepare statement: " . $db->errstr;
		$sth2->execute() or die "Couldn't execute statement: " . $sth2->errstr;

		while (my @data2 = $sth2->fetchrow_array()) {
			my $exten = $data2[0];
			$exten =~ s/\n//g;
			my $auth = $data2[1];
			$auth =~ s/\n//g;

			my $sth3 = $db->prepare("SELECT pass FROM users WHERE $search AND user='".$data2[0]."' ORDER BY host ASC") or die "Couldn't prepare statement: " . $db->errstr;
			$sth3->execute() or die "Couldn't execute statement: " . $sth3->errstr;
			my $pass = '';

			while (my @data3 = $sth3->fetchrow_array()) {
				$pass = $data3[0];
				$pass =~ s/\n//g;
			}

			if ($pass eq "") { print "\t[-] exten: $exten \t- $auth\n"; }
			else { print "\t[-] exten: $exten \t- $auth \t- pass: $pass\n"; }
		}

		print "\n";
	}
	
	$sth->finish;

	print "\n";

	exit;
}

 
sub help {
    print qq{
SipREPORT v1.2 - by Pepelux <pepeluxx\@gmail.com>
--------------

Usage: perl $0 -h <host>
 
== Examples ==
\$perl $0 -h 192.168.0.1
\tTo show all data in database for host 192.168.0.1
\$perl $0 -h 192.168.0.0
\tTo show all data in database for network 192.168.0.0

};
 
    exit 1;
}
 
init();
