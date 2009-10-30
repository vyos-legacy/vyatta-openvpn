#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
require Vyatta::OpenVPN::Config;

my $vtun = shift;

my $config = new Vyatta::OpenVPN::Config;
my $oconfig = new Vyatta::OpenVPN::Config;
$config->setup($vtun);
$oconfig->setupOrig($vtun);

if (!($config->isDifferentFrom($oconfig))) {
  # config not changed. do nothing.
  exit 0;
}

if ($config->isEmpty()) {
  # deleted
  $config->kill_daemon();
  exit 0;
}

my ($cmd, $err) = $config->get_command();
if (defined($cmd)) {
  $config->kill_daemon();
  system("$cmd");
  if ($? >> 8) {
    $err = 'Failed to start OpenVPN tunnel';
  }
}
if (defined($err)) {
  print STDERR "OpenVPN configuration error: $err.\n";
  exit 1;
}

exit 0;

