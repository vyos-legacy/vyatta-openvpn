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
  _remote_host   => [],
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
  _tls_crl       => undef,
  _tls_role      => undef,
  _client_ip     => [],
  _client_subnet => [],
  _topo          => undef,
  _proto         => undef,
  _local_port    => undef,
  _remote_port   => undef,
  _r_def_route   => undef,
  _r_def_rt_loc  => undef,
  _encrypt       => undef,
  _hash          => undef,
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
  my @tmp = $config->returnValues('remote-host');
  $self->{_remote_host} = \@tmp;
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
  $self->{_tls_crl} = $config->returnValue('tls crl-file');
  $self->{_tls_role} = $config->returnValue('tls role');
  $self->{_tls_def} = (defined($self->{_tls_ca})
                       || defined($self->{_tls_cert})
                       || defined($self->{_tls_key})
                       || defined($self->{_tls_crl})
                       || defined($self->{_tls_role})
                       || defined($self->{_tls_dh})) ? 1 : undef;
  my @clients = $config->listNodes('server client');
  # client IPs
  my @cips = ();
  for my $c (@clients) {
    my $ip = $config->returnValue("server client $c ip");
    if (defined($ip)) {
      push @cips, [ $c, $ip ];
    }
  }
  $self->{_client_ip} = \@cips;
  # client subnets 
  my @csubs = ();
  for my $c (@clients) {
    my $s = $config->returnValue("server client $c subnet");
    if (defined($s)) {
      push @csubs, [ $c, $s ];
    }
  }
  $self->{_client_subnet} = \@csubs;

  $self->{_topo} = $config->returnValue('server topology');
  $self->{_proto} = $config->returnValue('protocol');
  $self->{_local_port} = $config->returnValue('local-port');
  $self->{_remote_port} = $config->returnValue('remote-port');
  $self->{_r_def_route} = $config->exists('replace-default-route');
  $self->{_r_def_rt_loc} = $config->exists('replace-default-route local');
  $self->{_encrypt} = $config->returnValue('encryption');
  $self->{_hash} = $config->returnValue('hash');

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
  my @tmp = $config->returnOrigValues('remote-host');
  $self->{_remote_host} = \@tmp;
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
  $self->{_tls_crl} = $config->returnOrigValue('tls crl-file');
  $self->{_tls_role} = $config->returnOrigValue('tls role');
  $self->{_tls_def} = (defined($self->{_tls_ca})
                       || defined($self->{_tls_cert})
                       || defined($self->{_tls_key})
                       || defined($self->{_tls_crl})
                       || defined($self->{_tls_role})
                       || defined($self->{_tls_dh})) ? 1 : undef;
  my @clients = $config->listOrigNodes('server client');
  # client IPs
  my @cips = ();
  for my $c (@clients) {
    my $ip = $config->returnOrigValue("server client $c ip");
    if (defined($ip)) {
      push @cips, [ $c, $ip ];
    }
  }
  $self->{_client_ip} = \@cips;
  # client subnets 
  my @csubs = ();
  for my $c (@clients) {
    my $s = $config->returnOrigValue("server client $c subnet");
    if (defined($s)) {
      push @csubs, [ $c, $s ];
    }
  }
  $self->{_client_subnet} = \@csubs;

  $self->{_topo} = $config->returnOrigValue('server topology');
  $self->{_proto} = $config->returnOrigValue('protocol');
  $self->{_local_port} = $config->returnOrigValue('local-port');
  $self->{_remote_port} = $config->returnOrigValue('remote-port');
  $self->{_r_def_route} = $config->existsOrig('replace-default-route');
  $self->{_r_def_rt_loc} = $config->existsOrig('replace-default-route local');
  $self->{_encrypt} = $config->returnOrigValue('encryption');
  $self->{_hash} = $config->returnOrigValue('hash');

  return 0;
}

sub listsDiff {
  my @a = @{$_[0]};
  my @b = @{$_[1]};
  return 1 if ((scalar @a) != (scalar @b));
  while (my $a = shift @a) {
    my $b = shift @b;
    return 1 if ($a ne $b);
  }
  return 0;
}

sub pairListsDiff {
  my @a = @{$_[0]};
  my @b = @{$_[1]};
  return 1 if (scalar(@a) != scalar(@b));
  for my $i (0 .. (scalar(@a) - 1)) {
    my @L1 = @{$a[$i]};
    my @L2 = @{$b[$i]};
    return 1 if ($L1[0] ne $L2[0] || $L1[1] ne $L2[1]);
  }
  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_local_addr} ne $that->{_local_addr});
  return 1 if ($this->{_local_host} ne $that->{_local_host});
  return 1 if ($this->{_remote_addr} ne $that->{_remote_addr});
  return 1 if (listsDiff($this->{_remote_host}, $that->{_remote_host}));
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
  return 1 if ($this->{_tls_crl} ne $that->{_tls_crl});
  return 1 if ($this->{_tls_role} ne $that->{_tls_role});
  return 1 if ($this->{_tls_def} ne $that->{_tls_def});
  return 1 if (pairListsDiff($this->{_client_ip}, $that->{_client_ip}));
  return 1 if (pairListsDiff($this->{_client_subnet},
                             $that->{_client_subnet}));
  return 1 if ($this->{_topo} ne $that->{_topo});
  return 1 if ($this->{_proto} ne $that->{_proto});
  return 1 if ($this->{_local_port} ne $that->{_local_port});
  return 1 if ($this->{_remote_port} ne $that->{_remote_port});
  return 1 if ($this->{_r_def_route} ne $that->{_r_def_route});
  return 1 if ($this->{_r_def_rt_loc} ne $that->{_r_def_rt_loc});
  return 1 if ($this->{_encrypt} ne $that->{_encrypt});
  return 1 if ($this->{_hash} ne $that->{_hash});

  return 0;
}

my %encryption_cmd_hash = (
  'des' => ' --cipher des-cbc',
  '3des' => ' --cipher des-ede3-cbc',
  'bf128' => ' --cipher bf-cbc --keysize 128',
  'bf256' => ' --cipher bf-cbc --keysize 256',
  'aes128' => ' --cipher aes-128-cbc',
  'aes192' => ' --cipher aes-192-cbc',
  'aes256' => ' --cipher aes-256-cbc',
);

my %hash_cmd_hash = (
  'md5' => ' --auth md5',
  'sha1' => ' --auth sha1',
  'sha256' => ' --auth sha256',
  'sha512' => ' --auth sha512',
);

sub get_command {
  my ($self) = @_;
  my $cmd = '/usr/sbin/openvpn --daemon --verb 3';

  # status
  $cmd .= " --status $status_dir/$self->{_intf}.status $status_itvl";
 
  # interface
  $cmd .= " --dev-type tun --dev $self->{_intf}";

  my ($tcp_p, $tcp_a) = (0, 0);
  if (defined($self->{_proto})) {
    if ($self->{_proto} eq 'tcp-passive') {
      $tcp_p = 1;
    } elsif ($self->{_proto} eq 'tcp-active') {
      $tcp_a = 1;
    }
  }

  # mode
  my ($client, $server, $topo) = (0, 0, 'subnet');
  return (undef, 'Must specify "mode"') if (!defined($self->{_mode}));
  if ($self->{_mode} eq 'client') {
    return (undef, 'Cannot specify "local-port" in client mode')
      if (defined($self->{_local_port}));
    return (undef, 'Cannot specify "local-host" in client mode')
      if (defined($self->{_local_host}));
    return (undef, 'Protocol "tcp-passive" is not valid in client mode')
      if ($tcp_p);
    $client = 1;
    $cmd .= ' --client --nobind';
  } elsif ($self->{_mode} eq 'server') {
    return (undef, 'Protocol "tcp-active" is not valid in server mode')
      if ($tcp_a);
    $server = 1;
    # note: "topology subnet" doesn't seem to provide client isolation.
    #       "topology p2p" is not compatible with Windows.
    if (defined($self->{_topo}) && $self->{_topo} eq 'point-to-point') {
      $topo = 'p2p';
    }
    $cmd .= " --mode server --tls-server --topology $topo";
    $cmd .= " --keepalive $ping_itvl $ping_restart";
  } else {
    # site-to-site
    $cmd .= " --ping $ping_itvl --ping-restart $ping_restart";
  }
    
  return (undef, 'The "topology" option is only valid in server mode')
    if (!$server && defined($self->{_topo}));

  # tunnel addresses (site-to-site only)
  if (!$client && !$server) {
    return (undef, 'Must specify "local-address"')
      if (!defined($self->{_local_addr}));
    return (undef, 'Must specify "remote-address"')
      if (!defined($self->{_remote_addr}));
   
    if (defined($self->{_local_host})
        && $self->{_local_addr} eq $self->{_local_host}) {
      return (undef, '"local-address" cannot be the same as "local-host"');
    }
    if (scalar(@{$self->{_remote_host}}) > 0) {
      for my $rem (@{$self->{_remote_host}}) {
        return (undef, '"remote-address" cannot be the same as "remote-host"')
          if ($rem eq $self->{_remote_addr});
      }
    }

    $cmd .= " --ifconfig $self->{_local_addr} $self->{_remote_addr}";
  } else {
    return (undef, 'Cannot specify "local-address" or "remote-address" in '
                   . 'client-server mode')
      if (defined($self->{_local_addr}) || defined($self->{_remote_addr}));
  }

  # local host
  if (defined($self->{_local_host})) {
    return (undef, 'Cannot specify "local-host" with "tcp-active"')
      if ($tcp_a);
    # we can check if the address is present
    $cmd .= " --local $self->{_local_host}";
  }
  
  # local port
  if (defined($self->{_local_port})) {
    return (undef, 'Cannot specify "local-port" with "tcp-active"')
      if ($tcp_a);
    $cmd .= " --lport $self->{_local_port}";
  }
  
  # remote port
  if (defined($self->{_remote_port})) {
    return (undef, 'Cannot specify "remote-port" in server mode') if ($server);
    $cmd .= " --rport $self->{_remote_port}";
  }

  # protocol
  if ($tcp_p) {
    $cmd .= " --proto tcp-server";
  } elsif ($tcp_a) {
    $cmd .= " --proto tcp-client";
  }

  # remote host
  if (scalar(@{$self->{_remote_host}}) > 0) {
    # not allowed in server mode
    return (undef, 'Cannot specify "remote-host" in server mode') if ($server);
    return (undef,
            'Cannot specify more than 1 "remote-host" with "tcp-passive"')
      if ($tcp_p && (scalar(@{$self->{_remote_host}}) > 1));

    for my $rhost (@{$self->{_remote_host}}) {
      if (!VyattaTypeChecker::validateType('ipv4', $rhost, 1)) {
        if (!($rhost =~ /^[-a-zA-Z0-9.]+$/)) {
          return (undef, 'Must specify IP or hostname for "remote-host"');
        }
      }
      $cmd .= " --remote $rhost";
    }
  } elsif ($client) {
    return (undef, 'Must specify "remote-host" in client mode');
  } elsif ($tcp_a) {
    return (undef, 'Must specify "remote-host" with "tcp-active"');
  }
  # site-to-site: if remote host not defined, no "--remote" (same as "--float")

  # remote subnet
  if (defined($self->{_remote_subnet})) {
    my $s = new NetAddr::IP "$self->{_remote_subnet}";
    my $n = $s->addr();
    my $m = $s->mask();
    $cmd .= " --route $n $m";
  }

  # encryption
  if (defined($self->{_encrypt})) {
    return (undef, "\"$self->{_encrypt}\" is not a valid algorithm")
      if (!defined($encryption_cmd_hash{$self->{_encrypt}}));
    $cmd .= $encryption_cmd_hash{$self->{_encrypt}};
  }

  # hash
  if (defined($self->{_hash})) {
    return (undef, "\"$self->{_hash}\" is not a valid algorithm")
      if (!defined($hash_cmd_hash{$self->{_hash}}));
    $cmd .= $hash_cmd_hash{$self->{_hash}};
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
   
    if (defined($self->{_tls_crl})) {
      return (undef, "Specified crl-file \"$self->{_tls_crl}\" is not valid")
        if (! -r $self->{_tls_crl});
      $cmd .= " --crl-verify $self->{_tls_crl}";
    }

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
    
    if (defined($self->{_tls_role})) {
      # have role
      return (undef, 'Cannot specify "tls role" in client-server mode')
        if ($client || $server);
      if ($self->{_tls_role} eq 'active') {
        return (undef, 
                'Cannot specify "tcp-passive" when "tls role" is "active"')
          if ($tcp_p);
        return (undef,
                'Cannot specify "tls dh-file" when "tls role" is "active"')
          if (defined($self->{_tls_dh}));
        $cmd .= ' --tls-client';
      } elsif ($self->{_tls_role} eq 'passive') {
        return (undef, 
                'Cannot specify "tcp-active" when "tls role" is "passive"')
          if ($tcp_a);
        return (undef,
                'Must specify "tls dh-file" when "tls role" is "passive"')
          if (!defined($self->{_tls_dh}));
        $cmd .= ' --tls-server';
      }
    } else {
      # no role
      return (undef, 'Must specify "tls role" in site-to-site mode')
        if (!$client && !$server);
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
    if (defined($self->{_r_def_route})) {
      if (defined($self->{_r_def_rt_loc})) {
        $cmd .= ' --push "redirect-gateway local" ';
      } else {
        $cmd .= ' --push "redirect-gateway" ';
      }
    }

    return (undef, 'Must specify "server subnet" option in server mode')
      if (!defined($self->{_server_def}));
    my $s = new NetAddr::IP "$self->{_server_subnet}";
    my $n = $s->addr();
    my $m = $s->mask();
    $cmd .= " --server $n $m";

    # per-client config specified. write them out.
    if (scalar(@{$self->{_client_ip}}) > 0
        || scalar(@{$self->{_client_subnet}}) > 0) {
      system("rm -f $ccd_dir/*");
      return (undef, 'Cannot generate per-client configurations') if ($? >> 8);
      for my $ref (@{$self->{_client_ip}}) {
        my $client = ${$ref}[0];
        my $ip = ${$ref}[1];
        my $cip = new NetAddr::IP "$ip/32";
        return (undef, "Client IP \"$ip\" is not in $self->{_server_subnet}")
          if (!$cip->within($s));
        my $ip1 = $s->first()->addr();
        if ($topo eq 'subnet') {
          $ip1 = $m;
        }
        # note: with "topology subnet", this is "<ip> <netmask>".
        #       with "topology p2p", this is "<ip> <our_ip>".
        system("echo \"ifconfig-push $ip $ip1\" >> $ccd_dir/$client");
        return (undef, 'Cannot generate per-client configurations')
          if ($? >> 8);
      }
      for my $ref (@{$self->{_client_subnet}}) {
        my $client = ${$ref}[0];
        my $cs = new NetAddr::IP "${$ref}[1]";
        my $cn = $cs->addr();
        my $cm = $cs->mask();
        system("echo \"iroute $cn $cm\" >> $ccd_dir/$client");
        return (undef, 'Cannot generate per-client configurations')
          if ($? >> 8);
      }
    }
    $cmd .= " --client-config-dir $ccd_dir";
  } else {
    if (defined($self->{_r_def_route})) {
      return (undef,
              'Cannot set "replace-default-route" without "remote-host"')
        if (scalar(@{$self->{_remote_host}}) <= 0);

      if (defined($self->{_r_def_rt_loc})) {
        $cmd .= ' --redirect-gateway local ';
      } else {
        $cmd .= ' --redirect-gateway ';
      }
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
  $str .= "\n  remote_host " . (join ' ', @{$self->{_remote_host}});
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

