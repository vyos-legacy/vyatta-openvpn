#!/usr/bin/perl

use strict;

my $STATUS_PATH = '/opt/vyatta/etc/openvpn/status';

if (!opendir(SDIR, "$STATUS_PATH")) {
  print STDERR "Cannot get status information\n";
  exit 1;
}
my @vtuns = grep { /\.status$/ } readdir(SDIR);
closedir(SDIR);
if ((scalar @vtuns) <= 0) {
  print STDERR "Cannot find active OpenVPN tunnels\n";
  exit 1;
}

sub stat2str {
  my $stat = shift;
  return 'N/A' if (!defined($stat));
  if ($stat > 1000000000) {
    $stat = sprintf('%.1fG', ($stat / 1000000000));
  } elsif ($stat > 1000000) {
    $stat = sprintf('%.1fM', ($stat / 1000000));
  } elsif ($stat > 1000) {
    $stat = sprintf('%.1fK', ($stat / 1000));
  }
  return $stat;
}

sub output_server_status {
  my $intf = shift;
  my @lines = @_;
  if (!($lines[0] =~ /^OpenVPN CLIENT LIST$/)) {
    return 0;
  }
  $lines[1] =~ /^Updated,(.*)$/;
  print <<EOH;
OpenVPN server status on $intf (last updated on $1)

Client          Remote IP       Tunnel IP       TX byte RX byte Connected Since
--------------- --------------- --------------- ------- ------- ------------------------
EOH

  my @clients = ();
  my @routes = ();
  my $i = 3;
  while (!($lines[$i] =~ /^ROUTING TABLE$/)) {
    push @clients, $lines[$i];
    $i++;
  }
  $i++;
  while (!($lines[$i] =~ /^GLOBAL STATS$/)) {
    push @routes, $lines[$i];
    $i++;
  }

  for (@clients) {
    my ($name, $rip_str, $recv, $sent, $since) = split /,/;
    chomp $since;
    my @croutes = grep { /^[^,]+,$name,/ } @routes;
    $croutes[0] =~ /^([^,]+),/;
    my $tip = $1;
    $rip_str =~ /^([^:]+):/;
    my $rip = $1;
    my $rbytes = stat2str($recv);
    my $sbytes = stat2str($sent);

    printf "%-15s %-15s %-15s %7s %7s %s\n",
           $name, $rip, $tip, $sbytes, $rbytes, $since;
  }

  print "\n\n";

  return 1;
}

my $status_shown = 0;
foreach my $vtun (@vtuns) {
  $vtun =~ /^(.*)\.status$/;
  my $intf = $1;
  if (!open(VT, "$STATUS_PATH/$vtun")) {
    print STDERR "Cannot get status for \"$intf\"\n";
    next;
  }
  my @slines = <VT>;
  close VT;
  if (output_server_status($intf, @slines)) {
    $status_shown = 1;
  }
}
if (!$status_shown) {
  print STDERR "Cannot find active OpenVPN servers\n";
  exit 1;
}

exit 0;

