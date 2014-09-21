#!/usr/bin/perl
#
# Module: vyatta-reset-client-ovpn.pl
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2007 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Deepti Kulkarni
# Date: March 2011
# Description: Script to reset openvpn client process
#
# **** End License ****
#

use strict;
use IO::Socket::UNIX qw( SOCK_STREAM );
use Getopt::Long;

my $cn;
GetOptions("cn=s" => \$cn);
my $socket_path = '/tmp/openvpn-mgmt-intf';
my $line;

##Main
unless (-e "/tmp/openvpn-mgmt-intf") {
    print "This command is only supported by OpenVPN in server mode\n";
    exit 1;
}

my $socket = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $socket_path,)
    or die("Cannot connect to management interface\n");

chomp($line = <$socket>);

sub reset_client {
    my $cn = shift;
    print $socket "kill $cn\n";
    chomp($line = <$socket>);
    if ($line =~ /SUCCESS/) {
        print "Client with Common-Name '$cn' has been reset.\n";
        return 0;
    } elsif ($line =~ /ERROR/) {
        return 1;
    }
}

if ($cn) {
    if (reset_client($cn)) {
        print "Invalid Common-Name\n";
        exit 1;
    }
}

shutdown($socket, 2)
    or die("Error closing the socket\n");
exit 0;
