#!/usr/bin/perl

use strict;
use Getopt::Long;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;

#valid modes
my %mode_hash = ( 
  'server'	=> \&output_server_status,
  'client'	=> \&output_client_status,
  'site-to-site' => \&output_sitetosite_status,
);

##main
my $mode;
my $client;

GetOptions("mode=s" => \$mode,
           "show=s" => \$client);

my $STATUS_PATH = '/opt/vyatta/etc/openvpn/status';
show_client_names($client)            if ($client);

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
  my $config = new Vyatta::Config;
  $config->setLevel("interfaces openvpn $intf");
  my $desc = $config->returnOrigValue("description");
   
  if (!($lines[0] =~ /^OpenVPN CLIENT LIST$/)) {
    return 0;
  }
  print <<EOH;
OpenVPN server status on $intf [$desc] 

Client CN       Remote IP       Tunnel IP       TX byte RX byte Connected Since
--------------- --------------- --------------- ------- ------- ------------------------
EOH

  my @clients = ();
  my %routes = ();
  my $i = 3;
  while (!($lines[$i] =~ /^ROUTING TABLE$/)) {
    push @clients, $lines[$i];
    $i++;
  }
  $i++;
  while (!($lines[$i] =~ /^GLOBAL STATS$/)) {
    my ($tip, $rip) = (split /,/, $lines[$i])[0,2];
    $routes{$rip} = $tip; 
    $i++;
  }

  for (@clients) {
    my ($name, $rip_str, $recv, $sent, $since) = split /,/;
    chomp $since;
    my $tip_str = $routes{$rip_str}; 
    my $rip = (split /:/, $rip_str)[0];
    my $rbytes = stat2str($recv);
    my $sbytes = stat2str($sent);

    printf "%-15s %-15s %-15s %7s %7s %s\n",
           $name, $rip, $tip_str, $sbytes, $rbytes, $since;
  }

  print "\n\n";

  return 1;
}

sub parse_status {
  my ($intf, $mode, @lines) = @_; 
  my @values = (); 
  my $config = new Vyatta::Config;
  if (!($lines[0] =~ /^OpenVPN STATISTICS$/)) {
    return 0;
  }
  my $rbytes;
  my $sbytes;
  my $i = 2;
  while (!($lines[$i] =~ /^Auth/)) {
   if ($lines[$i] =~ /^[A-Z\/]+ read bytes/) {
     my @recv = split (/,/,$lines[$i]);
     $rbytes = $rbytes + $recv[1];
   }
   elsif ($lines[$i] =~ /^[A-Z\/]+ write bytes/) {
     my @sent = split (/,/,$lines[$i]);
     $sbytes = $sbytes + $sent[1];
   }
   $i++;
  }
   my $recv = stat2str($rbytes);
   my $sent = stat2str($sbytes);
   $config->setLevel("interfaces openvpn $intf");
   my $desc = $config->returnOrigValue("description");
   my @remote = $config->returnOrigValues("remote-host");
   if ((scalar @remote) > 1) {
     $remote[0] = "N/A";
   }
   push (@values, $desc, $remote[0]);
   push (@values, $sent, $recv);
   if ($mode eq "site-to-site") {
     my $rsite = "N/A"; 
     my $rtunnel = $config->returnOrigValue("remote-address");
     if ($config->existsOrig("shared-secret-key-file")) {
      $rsite = "None (PSK)";
     }
     push (@values, $rsite, $rtunnel); 
   }
   return @values;
}

sub parse_common_name  {
  my $intf = shift;
  my @lines = @_;
  my @clients = ();
  my @cn;
  my $i = 3;
  while (!($lines[$i] =~ /^ROUTING TABLE$/)) {
    push @clients, $lines[$i];
    $i++;
  }
  for (@clients) {
    my ($name, $rip_str, $recv, $sent, $since) = split /,/;
    push @cn, $name;
  }
  print join(' ', @cn), "\n";
}

# generate one line with all client CN's for allowed
sub show_client_names {
  my $mode = "server";
  my $client = shift;
  if (!opendir(SDIR, "$STATUS_PATH")) {
    exit 1;
  }
  my @vtuns = grep { /\.status$/ } readdir(SDIR);
  closedir(SDIR);
  if ((scalar @vtuns) <= 0) {
    exit 1;
  }
  my $config = new Vyatta::Config;
  foreach my $vtun (@vtuns) {
    $vtun =~ /^(.*)\.status$/;
    my $intf = $1;
    $config->setLevel("interfaces openvpn $intf");
    my $modeVal = $config->returnOrigValue("mode");
    if ($mode eq $modeVal) {
    if (!open(VT, "$STATUS_PATH/$vtun")) {
      next;
    }
    my @slines = <VT>;
    close VT;
    parse_common_name($intf, @slines);
    }
  }
  exit 0;
}

sub output_client_status {
  my $intf = shift;
  my @lines = @_;
  my $mode = "client"; 
  my ($desc, $remote, $sent, $recv) = parse_status($intf, $mode, @lines); 
  print <<EOH;
OpenVPN client status on $intf [$desc]

Server CN       Remote IP       Tunnel IP       TX byte RX byte Connected Since
--------------- --------------- --------------- ------- ------- ------------------------
EOH
 
  printf "%-15s %-15s %-15s %7s %7s %s\n",
           "N/A", $remote, "N/A", $sent, $recv, "N/A";
  print "\n\n";
  return 1;
}


sub output_sitetosite_status {
  my $intf = shift;
  my @lines = @_;
  my $mode = "site-to-site";
  my ($desc, $remote, $sent, $recv, $rsite, $rtunnel) = parse_status($intf, $mode, @lines); 
  print <<EOH;
OpenVPN client status on $intf [$desc] 

Remote CN       Remote IP       Tunnel IP       TX byte RX byte Connected Since
--------------- --------------- --------------- ------- ------- ------------------------
EOH
  printf "%-15s %-15s %-15s %7s %7s %s\n",
           $rsite, $remote, $rtunnel, $sent, $recv, "N/A";
  print "\n\n";
  return 1;
}

my $status_shown = 0;
my $config = new Vyatta::Config;
foreach my $vtun (@vtuns) {
  $vtun =~ /^(.*)\.status$/;
  my $intf = $1;
  $config->setLevel("interfaces openvpn $intf");
  my $modeVal = $config->returnOrigValue("mode"); 
  if ($mode eq $modeVal) {
   if (!open(VT, "$STATUS_PATH/$vtun")) {
    print STDERR "Cannot get status for \"$intf\"\n";
    next;
   }
   my @slines = <VT>;
   close VT;
   my $func;
   if (defined $mode_hash{$mode}) {
    $func = $mode_hash{$mode};
   } 
   if (&$func($intf, @slines)) {
    $status_shown = 1;
   }
  }
 }
if (!$status_shown) {
  print STDERR "Cannot find active OpenVPN $mode connections\n";
  exit 1;
}

exit 0;

