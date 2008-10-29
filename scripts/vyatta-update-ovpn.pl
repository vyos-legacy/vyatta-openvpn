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

my $PGREP = "pgrep -f '^/usr/sbin/openvpn .* --dev $vtun --'";

sub wait_until_dead {
  my $kill_repeatedly = shift;
  my ($i, $done) = (0, 0);
  while ($i < 10) {
    if ($kill_repeatedly) {
      system("kill -9 `$PGREP` >&/dev/null");
    }
    system("$PGREP >&/dev/null");
    if ($? >> 8) {
      $done = 1;
      last;
    }
    sleep 1;
    $i++;
  }
  return 1 if ($done); # dead
  return 0; # alive
}

sub kill_daemon {
  system("$PGREP >&/dev/null");
  if ($? >> 8) {
    # not present
    return;
  }

  # kill politely
  system("kill -TERM `$PGREP` >&/dev/null");
  if ($? >> 8) {
    print STDERR "OpenVPN configuration error: Failed to stop tunnel.\n";
    exit 1;
  }
  return if (wait_until_dead(0));
  
  # still alive. kill forcefully.
  system("kill -9 `$PGREP` >&/dev/null");
  if (!wait_until_dead(1)) {
    # undead
    print STDERR "OpenVPN configuration error: Failed to stop tunnel.\n";
    exit 1;
  }
}

if ($config->isEmpty()) {
  # deleted
  kill_daemon();
  exit 0;
}

my ($cmd, $err) = $config->get_command();
if (defined($cmd)) {
  kill_daemon();
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

