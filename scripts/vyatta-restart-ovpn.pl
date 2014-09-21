#!/usr/bin/perl
#
# Module: vyatta-restart-ovpn.pl
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
# Date: Oct 2010
# Description: Script to restart openvpn process
#
# **** End License ****
#

use lib "/opt/vyatta/share/perl5/";
use strict;
use IO::Prompt;
use Getopt::Long;
use Vyatta::Interface;
use Vyatta::Config;

my $vtun;
my $pid;
my $cmd = 'kill -USR1 ';
my $reset_persistent = 0;

sub is_valid_intf {
    my $name = shift;
    my $intf = new Vyatta::Interface($name);
    return unless $intf;

    return $intf->exists();
}

sub is_persistent {
    my $intf = shift;
    my $config = new Vyatta::Config;

    $config->setLevel("interfaces openvpn $intf");
    
    return $config->existsOrig('persistent-tunnel');
}

## Main

GetOptions("vtun=s" => \$vtun);
if ($vtun) {
    die "Invalid interface [$vtun]\n"
        unless is_valid_intf($vtun);
}

print "\nThis will reset and re-establish all tunnel connections on this interface.\n";

if ((defined($ENV{VYATTA_PROCESS_CLIENT}) && $ENV{VYATTA_PROCESS_CLIENT} eq 'gui2_rest') || prompt("Are you sure you want to continue? (y/n)", -y1d=>"y")) {
    if (is_persistent($vtun)) {
        print "\nThis interface has been configured as a persistent tunnel, so will be reused.\n";
        if (prompt("Do you want to reset the interface as well? (y/n)", -y1d=>"y")) {
            # Send SIGHUP rather than SIGUSR1 to force the interface to reset
            $reset_persistent = 1;
            $cmd = 'kill -HUP ';
        }
    }
    $pid = `cat /var/run/openvpn-$vtun.pid`;
    if ($pid) {
        $cmd .= "$pid";
        system($cmd);
        if ($reset_persistent) {
            print "\nBoth the tunnel connections and interface for $vtun have been reset.\n";
        }else {
            print "\nTunnel connections for interface $vtun have been reset.\n";
        }
    } else {
        print "\nNo tunnel connection on interface $vtun.\n";
    }
} else {
    print "\nReset cancelled\n";
}
