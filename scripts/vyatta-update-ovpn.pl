#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaOVPNConfig;

my $vtun = shift;

my $config = new VyattaOVPNConfig;
my $oconfig = new VyattaOVPNConfig;
$config->setup($vtun);
$oconfig->setupOrig($vtun);

if (!($config->isDifferentFrom($oconfig))) {
  # config not changed. do nothing.
  exit 0;
}

# config for this interface changed. kill the daemon instance.
system("kill -TERM `pgrep -f 'openvpn .* --dev $vtun --'` >&/dev/null");
if ($? >> 8) {
  print STDERR "OpenVPN configuration error: Failed to stop tunnel.\n";
  exit 1;
}

# if deleted, we're done
exit 0 if ($config->isEmpty());

my ($cmd, $err) = $config->get_command();
if (defined($cmd)) {
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

