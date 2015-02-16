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

my $host = '';	# host
my $ua = '';	# user-agent
my $noexten = 0;
my $noauth = 0;

my $database = "sippts.db";

unless (-e $database) {
	die("Database $database not found\n\n");
}
	
my $db = DBI->connect("dbi:SQLite:dbname=$database","","") or die $DBI::errstr;

sub init() {
    # check params
    my $result = GetOptions ("h=s" => \$host,
				"u=s" => \$ua,
				"noauth+" => \$noauth,
				"noexten+" => \$noexten);
 
	help() if ($host eq "" && $ua eq "");
	
	my @data;
	my $search = "";

	if ($host ne "" && $host ne ".") {
		@data = split(/\./, $host);
		if ($data[3] eq "0") { $search = "host LIKE '".$data[0].".".$data[1].".".$data[2].".%'"; }
		else { $search = "host='$host'"; }
	}
	else {
		if ($host eq ".") { $search = "1=1"; }
		else {$search = "useragent LIKE '%$ua%'"; }
	}
 
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
		print "[+] $host:$port/$proto \t- UserAgent: $ua\n" if ($noauth eq 0);

		if ($noexten eq 0) {
			my $sql = "SELECT exten, auth FROM extens WHERE host='$host'";
			$sql .= " AND auth LIKE '%no auth%'" if ($noauth eq 1);
			$sql .= " ORDER BY host ASC";
			my $sth2 = $db->prepare($sql) or die "Couldn't prepare statement: " . $db->errstr;
			$sth2->execute() or die "Couldn't execute statement: " . $sth2->errstr;
			my $write = 0;

			while (my @data2 = $sth2->fetchrow_array()) {
				print "[+] $host:$port/$proto \t- UserAgent: $ua\n" if ($noauth eq 1 && $write eq 0);
				my $exten = $data2[0];
				$exten =~ s/\n//g;
				my $auth = $data2[1];
				$auth =~ s/\n//g;

				my $sth3 = $db->prepare("SELECT pass FROM users WHERE host='$host' AND user='".$data2[0]."' ORDER BY host ASC") or die "Couldn't prepare statement: " . $db->errstr;
				$sth3->execute() or die "Couldn't execute statement: " . $sth3->errstr;
				my $pass = '';

				while (my @data3 = $sth3->fetchrow_array()) {
					$pass = $data3[0];
					$pass =~ s/\n//g;
				}

				if ($pass eq "") { print "\t[-] exten: $exten \t- $auth\n"; }
				else { print "\t[-] exten: $exten \t- $auth \t- pass: $pass\n"; }

				$write = 1;
			}

			print "\n" if ($noauth eq 0 || ($noauth eq 1 && $write eq 1));
		}
	}
	
	$sth->finish;

	print "\n";

	exit;
}

 
sub help {
    print qq{
SipREPORT v1.2 - by Pepelux <pepeluxx\@gmail.com>
--------------

Usage: perl $0 -h <host> | -u <user-agent> [options]

== Options ==
-noexten    = Show only servers and devices (not extensions nor users)
-noauth     = Show extensions with authentication not required

== Examples ==
\$perl $0 -h 192.168.0.1
\tTo show all data in database for host 192.168.0.1
\$perl $0 -h 192.168.0.0
\tTo show all data in database for network 192.168.0.0
\$perl $0 -h .
\tTo show all data
\$perl $0 -h . -noauth
\tTo show all data with users without auth
\$perl $0 -u fpbx
\tTo show all FreePBX in database (with User-Agent: fpbx)

};
 
    exit 1;
}
 
init();
