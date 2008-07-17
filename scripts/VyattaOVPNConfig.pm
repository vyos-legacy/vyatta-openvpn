package VyattaOVPNConfig;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaTypeChecker;
use NetAddr::IP;

my $ccd_dir = '/opt/vyatta/etc/openvpn/ccd';
my $status_dir = '/opt/vyatta/etc/openvpn/status';
my $status_itvl = 30;
my $ping_itvl = 10;
my $ping_restart = 60;

my %fields = (
  _intf          => undef,
  _local_addr    => undef,
  _local_host    => undef,
  _remote_addr   => undef,
  _remote_host   => undef,
  _remote_subnet => undef,
  _options       => undef,
  _secret_file   => undef,
  _mode          => undef,
  _server_def    => undef,
  _server_subnet => undef,
  _tls_def       => undef,
  _tls_ca        => undef,
  _tls_cert      => undef,
  _tls_key       => undef,
  _tls_dh        => undef,
  _client_ip     => [],
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
  $self->{_mode} = $config->returnValue('mode');
  $self->{_server_subnet} = $config->returnValue('server subnet');
  $self->{_server_def} = (defined($self->{_server_subnet})) ? 1 : undef;
  $self->{_tls_ca} = $config->returnValue('tls ca-cert-file');
  $self->{_tls_cert} = $config->returnValue('tls cert-file');
  $self->{_tls_key} = $config->returnValue('tls key-file');
  $self->{_tls_dh} = $config->returnValue('tls dh-file');
  $self->{_tls_def} = (defined($self->{_tls_ca})
                       || defined($self->{_tls_cert})
                       || defined($self->{_tls_key})
                       || defined($self->{_tls_dh})) ? 1 : undef;
  my @clients = $config->listNodes('server client');
  my @cips = ();
  for my $c (@clients) {
    my $ip = $config->returnValue("server client $c ip");
    if (defined($ip)) {
      push @cips, [ $c, $ip ];
    }
  }
  $self->{_client_ip} = \@cips;

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
  $self->{_mode} = $config->returnOrigValue('mode');
  $self->{_server_subnet} = $config->returnOrigValue('server subnet');
  $self->{_server_def} = (defined($self->{_server_subnet})) ? 1 : undef;
  $self->{_tls_ca} = $config->returnOrigValue('tls ca-cert-file');
  $self->{_tls_cert} = $config->returnOrigValue('tls cert-file');
  $self->{_tls_key} = $config->returnOrigValue('tls key-file');
  $self->{_tls_dh} = $config->returnOrigValue('tls dh-file');
  $self->{_tls_def} = (defined($self->{_tls_ca})
                       || defined($self->{_tls_cert})
                       || defined($self->{_tls_key})
                       || defined($self->{_tls_dh})) ? 1 : undef;
  my @clients = $config->listOrigNodes('server client');
  my @cips = ();
  for my $c (@clients) {
    my $ip = $config->returnOrigValue("server client $c ip");
    if (defined($ip)) {
      push @cips, [ $c, $ip ];
    }
  }
  $self->{_client_ip} = \@cips;

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
  return 1 if ($this->{_mode} ne $that->{_mode});
  return 1 if ($this->{_server_subnet} ne $that->{_server_subnet});
  return 1 if ($this->{_server_def} ne $that->{_server_def});
  return 1 if ($this->{_tls_ca} ne $that->{_tls_ca});
  return 1 if ($this->{_tls_cert} ne $that->{_tls_cert});
  return 1 if ($this->{_tls_key} ne $that->{_tls_key});
  return 1 if ($this->{_tls_dh} ne $that->{_tls_dh});
  return 1 if ($this->{_tls_def} ne $that->{_tls_def});
  return 1 if (scalar(@{$this->{_client_ip}})
               != scalar(@{$that->{_client_ip}}));
  for my $i (0 .. (scalar(@{$this->{_client_ip}}) - 1)) {
    my @L1 = @{${$this->{_client_ip}}[$i]};
    my @L2 = @{${$that->{_client_ip}}[$i]};
    return 1 if ($L1[0] ne $L2[0] || $L1[1] ne $L2[1]);
  }
  
  return 0;
}

sub get_command {
  my ($self) = @_;
  my $cmd = '/usr/sbin/openvpn --daemon --verb 3';

  # status
  $cmd .= " --status $status_dir/$self->{_intf}.status $status_itvl";
 
  # interface
  $cmd .= " --dev-type tun --dev $self->{_intf}";

  # mode
  my ($client, $server) = (0, 0);
  return (undef, 'Must specify "mode"') if (!defined($self->{_mode}));
  if ($self->{_mode} eq 'client') {
    $client = 1;
    $cmd .= ' --client --nobind';
  } elsif ($self->{_mode} eq 'server') {
    $server = 1;
    $cmd .= ' --mode server --tls-server --topology subnet';
    $cmd .= " --keepalive $ping_itvl $ping_restart";
  } else {
    # site-to-site
    $cmd .= " --ping $ping_itvl --ping-restart $ping_restart";
  }

  # tunnel addresses (site-to-site only)
  if (!$client && !$server) {
    return (undef, 'Must specify "local-address"')
      if (!defined($self->{_local_addr}));
    return (undef, 'Must specify "remote-address"')
      if (!defined($self->{_remote_addr}));
    $cmd .= " --ifconfig $self->{_local_addr} $self->{_remote_addr}";
  } else {
    return (undef, 'Cannot specify "local-address" or "remote-address" in '
                   . 'client-server mode')
      if (defined($self->{_local_addr}) || defined($self->{_remote_addr}));
  }

  # local host
  if (defined($self->{_local_host})) {
    # we can check if the address is present
    $cmd .= " --local $self->{_local_host}";
  }

  # remote host
  if (defined($self->{_remote_host})) {
    # not allowed in server mode
    return (undef, 'Cannot specify "remote-host" in server mode') if ($server);

    if (!VyattaTypeChecker::validateType('ipv4', $self->{_remote_host})) {
      if (!($self->{_remote_host} =~ /^[-a-zA-Z0-9.]+$/)) {
        return (undef, 'Must specify IP or hostname for "remote-host"');
      }
    }
    $cmd .= " --remote $self->{_remote_host}";
  } elsif ($client) {
    return (undef, 'Must specify "remote-host" in client mode');
  }
  # site-to-site: if remote host not defined, no "--remote" (same as "--float")

  # remote subnet
  if (defined($self->{_remote_subnet})) {
    my $s = new NetAddr::IP "$self->{_remote_subnet}";
    my $n = $s->network();
    my $m = $s->mask();
    $cmd .= " --route $n $m";
  }

  # secret & tls
  return (undef, 'Must specify one of "shared-secret-key-file" and "tls"')
    if (!defined($self->{_secret_file}) && !defined($self->{_tls_def}));
  return (undef, 'Can only specify one of "shared-secret-key-file" '
                 . 'and "tls"')
    if (defined($self->{_secret_file}) && defined($self->{_tls_def}));
  return (undef, 'Must specify "tls" in client-server mode')
    if (($client || $server) && !defined($self->{_tls_def}));

  # tls
  if (defined($self->{_tls_def})) {
    return (undef, 'Must specify "tls ca-cert-file"')
      if (!defined($self->{_tls_ca}));
    return (undef, "Specified ca-cert-file \"$self->{_tls_ca}\" is not valid")
      if (! -r $self->{_tls_ca});
    $cmd .= " --ca $self->{_tls_ca}";
    
    return (undef, 'Must specify "tls cert-file"')
      if (!defined($self->{_tls_cert}));
    return (undef, "Specified cert-file \"$self->{_tls_cert}\" is not valid")
      if (! -r $self->{_tls_cert});
    $cmd .= " --cert $self->{_tls_cert}";
    
    return (undef, 'Must specify "tls key-file"')
      if (!defined($self->{_tls_key}));
    return (undef, "Specified key-file \"$self->{_tls_key}\" is not valid")
      if (! -r $self->{_tls_key});
    $cmd .= " --key $self->{_tls_key}";

    if (!defined($self->{_tls_dh})) {
      return (undef, 'Must specify "tls dh-file" in server mode')
        if ($server);
    } else {
      return (undef, 'Cannot specify "tls dh-file" in client mode')
        if ($client);
      return (undef, "Specified dh-file \"$self->{_tls_dh}\" is not valid")
        if (! -r $self->{_tls_dh});
      $cmd .= " --dh $self->{_tls_dh}";
    }
  }

  # secret file
  if (defined($self->{_secret_file})) {
    return (undef, 'Specified shared-secret-key-file '
                   . "\"$self->{_secret_file}\" is not valid")
      if (! -r $self->{_secret_file});
    # we can further validate the secret file
    $cmd .= " --secret $self->{_secret_file}";
  }

  # "server" subsection
  if ($server) {
    return (undef, 'Must specify "server" options in server mode')
      if (!defined($self->{_server_def}));
    my $s = new NetAddr::IP "$self->{_server_subnet}";
    my $n = $s->network();
    my $m = $s->mask();
    $cmd .= " --server $n $m";

    # per-client config specified. write them out.
    if (scalar(@{$self->{_client_ip}}) > 0) {
      system("rm -f $ccd_dir/*");
      return (undef, 'Cannot generate per-client configurations') if ($? >> 8);
      for my $ref (@{$self->{_client_ip}}) {
        my $client = ${$ref}[0];
        my $ip = ${$ref}[1];
        system("echo \"ifconfig-push $ip $m\" > $ccd_dir/$client");
        return (undef, 'Cannot generate per-client configurations')
          if ($? >> 8);
      }
      $cmd .= " --client-config-dir $ccd_dir";
    }
  }

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
  $str .= "\n  mode " . $self->{_mode};
  $str .= "\n  server_subnet " . $self->{_server_subnet};
  $str .= "\n  tls_ca " . $self->{_tls_ca};
  $str .= "\n  tls_cert " . $self->{_tls_cert};
  $str .= "\n  tls_key " . $self->{_tls_key};
  $str .= "\n  tls_dh " . $self->{_tls_dh};
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

1;

