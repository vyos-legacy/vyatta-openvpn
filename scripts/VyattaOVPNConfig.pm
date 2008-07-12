package VyattaOVPNConfig;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaTypeChecker;
use NetAddr::IP;

my %fields = (
  _intf          => undef,
  _local_addr    => undef,
  _local_host    => undef,
  _remote_addr   => undef,
  _remote_host   => undef,
  _remote_subnet => undef,
  _options       => undef,
  _secret_file   => undef,
  _is_empty         => 1,
);

my $iftype = 'interfaces openvpn';

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ($self, $intf) = @_;
  my $config = new VyattaConfig;

  $config->setLevel("$iftype $intf");
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }
  
  $self->{_intf} = $intf;
  $self->{_local_addr} = $config->returnValue('local-address');
  $self->{_local_host} = $config->returnValue('local-host');
  $self->{_remote_addr} = $config->returnValue('remote-address');
  $self->{_remote_host} = $config->returnValue('remote-host');
  $self->{_remote_subnet} = $config->returnValue('remote-subnet');
  $self->{_options} = $config->returnValue('openvpn-option');
  $self->{_secret_file} = $config->returnValue('shared-secret-key-file');

  return 0;
}

sub setupOrig {
  my ($self, $intf) = @_;
  my $config = new VyattaConfig;

  $config->setLevel("$iftype $intf");
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }
  
  $self->{_intf} = $intf;
  $self->{_local_addr} = $config->returnOrigValue('local-address');
  $self->{_local_host} = $config->returnOrigValue('local-host');
  $self->{_remote_addr} = $config->returnOrigValue('remote-address');
  $self->{_remote_host} = $config->returnOrigValue('remote-host');
  $self->{_remote_subnet} = $config->returnOrigValue('remote-subnet');
  $self->{_options} = $config->returnOrigValue('openvpn-option');
  $self->{_secret_file} = $config->returnOrigValue('shared-secret-key-file');

  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_local_addr} ne $that->{_local_addr});
  return 1 if ($this->{_local_host} ne $that->{_local_host});
  return 1 if ($this->{_remote_addr} ne $that->{_remote_addr});
  return 1 if ($this->{_remote_host} ne $that->{_remote_host});
  return 1 if ($this->{_remote_subnet} ne $that->{_remote_subnet});
  return 1 if ($this->{_options} ne $that->{_options});
  return 1 if ($this->{_secret_file} ne $that->{_secret_file});
  
  return 0;
}

sub get_command {
  my ($self) = @_;
  my $cmd = '/usr/sbin/openvpn --daemon --verb 3';
 
  # interface
  $cmd .= " --dev-type tun --dev $self->{_intf}";

  # tunnel addresses
  return (undef, 'Must specify "local-address"')
    if (!defined($self->{_local_addr}));
  return (undef, 'Must specify "remote-address"')
    if (!defined($self->{_remote_addr}));
  $cmd .= " --ifconfig $self->{_local_addr} $self->{_remote_addr}";

  # local host
  if (defined($self->{_local_host})) {
    # we can check if the address is present
    $cmd .= " --local $self->{_local_host}";
  }

  # remote host
  return (undef, 'Must specify "remote-host"')
    if (!defined($self->{_remote_host}));
  if (!VyattaTypeChecker::validateType('ipv4', $self->{_remote_host})) {
    if (!($self->{_remote_host} =~ /^[-a-zA-Z0-9.]+$/)) {
      return (undef, 'Must specify IP or hostname for "remote-host"');
    }
  }
  $cmd .= " --remote $self->{_remote_host}";

  # remote subnet
  if (defined($self->{_remote_subnet})) {
    my $s = new NetAddr::IP "$self->{_remote_subnet}";
    my $n = $s->network();
    my $m = $s->mask();
    $cmd .= " --route $n $m";
  }

  # secret file
  return (undef, 'Must specify "shared-secret-key-file"')
    if (!defined($self->{_secret_file}));
  return (undef, "Specified shared-secret-key-file \"$self->{_secret_file}\" "
                 . 'is not valid')
    if (! -r $self->{_secret_file});
  # we can further validate the secret file
  $cmd .= " --secret $self->{_secret_file}";

  # extra options
  if (defined($self->{_options})) {
    $cmd .= " $self->{_options}";
  }

  return ($cmd, undef);
}

sub print_str {
  my ($self) = @_;
  my $str = "openvpn $self->{_intf}";
  $str .= "\n  local_addr " . $self->{_local_addr};
  $str .= "\n  local_host " . $self->{_local_host};
  $str .= "\n  remote_addr " . $self->{_remote_addr};
  $str .= "\n  remote_host " . $self->{_remote_host};
  $str .= "\n  remote_subnet " . $self->{_remote_subnet};
  $str .= "\n  options " . $self->{_options};
  $str .= "\n  secret_file " . $self->{_secret_file};
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

1;

