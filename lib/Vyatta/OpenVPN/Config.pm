package Vyatta::OpenVPN::Config;

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::TypeChecker;
use NetAddr::IP;

my $ccd_dir = '/opt/vyatta/etc/openvpn/ccd';
my $status_dir = '/opt/vyatta/etc/openvpn/status';
my $upfile_dir = '/opt/vyatta/etc/openvpn/up';
my $status_itvl = 30;
my $ping_itvl = 10;
my $ping_restart = 60;

my %fields = (
  _intf          => undef,
  _description   => undef, 
  _local_addr    => undef,
  _local_host    => undef,
  _remote_addr   => undef,
  _remote_host   => [],
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
  _is_empty      => 1,
  _qos		 => undef,
  _bridge	 => undef,
  _bridgecost    => undef,
  _bridgeprio    => undef,
  _disable	 => undef,
  _name_server   => [],
  _push_route    => [],
  _client_route  => [],
  _server_mclients  => undef,
  _pam_login     => undef,
  _pam_username  => undef,
  _pam_password  => undef, 
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
  my $config = new Vyatta::Config;

  # set up ccd and up-directory for this interface
  $ccd_dir = "$ccd_dir/$intf";
  $upfile_dir = "$upfile_dir/$intf";
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
  $self->{_bridge} = $config->returnValue('bridge-group bridge');
  $self->{_bridgecost} = $config->returnValue('bridge-group cost');
  $self->{_bridgeprio} = $config->returnValue('bridge-group priority');
  $self->{_description} = $config->returnValue('description');
  my @nserver = $config->returnValues('server name-server');
  $self->{_name_server} = \@nserver;
  my @proute = $config->returnValues('server push-route');
  $self->{_push_route} = \@proute;
  $self->{_server_mclients} = $config->returnValue('server max-connections');
  if ( $config->exists('server require-pam-login') ) { $self->{_pam_login} = 1; }
  if ( $config->exists('disable') ) { $self->{_disable} = 1; }
  $self->{_pam_username} = $config->returnValue('username');
  $self->{_pam_password} = $config->returnValue('password');
  
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
    my @s = $config->returnValues("server client $c subnet");
    if (scalar(@s) >0) {
      push @csubs, [ $c, @s ];
    }
  }
  $self->{_client_subnet} = \@csubs;
  # client push routes
  my @croute = ();
  for my $c (@clients) {
   my @cproute = $config->returnValues("server client $c push-route");
   if (scalar(@cproute) >0) {
    push @croute, [ $c, @cproute ];
   } 
  } 
  $self->{_client_route} = \@croute;
  $self->{_topo} = $config->returnValue('server topology');
  $self->{_proto} = $config->returnValue('protocol');
  $self->{_local_port} = $config->returnValue('local-port');
  $self->{_remote_port} = $config->returnValue('remote-port');
  $self->{_r_def_route} = $config->exists('replace-default-route');
  $self->{_r_def_rt_loc} = $config->exists('replace-default-route local');
  $self->{_encrypt} = $config->returnValue('encryption');
  $self->{_hash} = $config->returnValue('hash');
  $self->{_qos} = $config->exists('qos-policy');

  return 0;
}

sub setupOrig {
  my ($self, $intf) = @_;
  my $config = new Vyatta::Config;

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
  $self->{_bridge} = $config->returnOrigValue('bridge-group bridge');
  $self->{_bridgecost} = $config->returnOrigValue('bridge-group cost');
  $self->{_bridgeprio} = $config->returnOrigValue('bridge-group priority');
  $self->{_description} = $config->returnOrigValue('description');
  my @nserver = $config->returnOrigValues('server name-server');
  $self->{_name_server} = \@nserver;
  my @proute = $config->returnOrigValues('server push-route');
  $self->{_push_route} = \@proute;
  $self->{_server_mclients} = $config->returnOrigValue('server max-connections');
  if ( $config->existsOrig('server require-pam-login') ) { $self->{_pam_login} = 1; }
  if ( $config->existsOrig('disable') ) { $self->{_disable} = 1; }
  $self->{_pam_username} = $config->returnOrigValue('username');
  $self->{_pam_password} = $config->returnOrigValue('password');

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
    my @s = $config->returnOrigValues("server client $c subnet");
    if (scalar(@s) >0) {
      push @csubs, [ $c, @s ];
    }
  }
  $self->{_client_subnet} = \@csubs;
  # client push routes
  my @croute = ();
  for my $c (@clients) {
   my @cproute = $config->returnOrigValues("server client $c push-route");
   if (scalar(@cproute) >0) {
    push @croute, [ $c, @cproute ];
   } 
  } 
  $self->{_client_route} = \@croute;

  $self->{_topo} = $config->returnOrigValue('server topology');
  $self->{_proto} = $config->returnOrigValue('protocol');
  $self->{_local_port} = $config->returnOrigValue('local-port');
  $self->{_remote_port} = $config->returnOrigValue('remote-port');
  $self->{_r_def_route} = $config->existsOrig('replace-default-route');
  $self->{_r_def_rt_loc} = $config->existsOrig('replace-default-route local');
  $self->{_encrypt} = $config->returnOrigValue('encryption');
  $self->{_hash} = $config->returnOrigValue('hash');
  $self->{_qos} = $config->returnValue('qos-policy');

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

sub doublePairDiff {
  my @a = @{$_[0]};
  my @b = @{$_[1]};
  return 1 if (scalar(@a) != scalar(@b));
  for my $i (0 .. (scalar(@a) - 1)) {
    my @L1 = @{$a[$i]};
    my @L2 = @{$b[$i]};
    return 1 if ((scalar @L1) != (scalar @L2));
    while (my $L1 = shift @L1) {
      my $L2 = shift @L2;
      return 1 if ($L1 ne $L2);
    }
  }
  return 0;
} 

# no restart of openvpn process required if clients/description is
# added/deleted 
sub isRestartNeeded {
  my ($this, $that) = @_;

  # suppress uninitialized warnings here
  no warnings qw(uninitialized);

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_local_addr} ne $that->{_local_addr});
  return 1 if ($this->{_local_host} ne $that->{_local_host});
  return 1 if ($this->{_remote_addr} ne $that->{_remote_addr});
  return 1 if (listsDiff($this->{_remote_host}, $that->{_remote_host}));
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
  return 1 if ($this->{_topo} ne $that->{_topo});
  return 1 if ($this->{_proto} ne $that->{_proto});
  return 1 if ($this->{_local_port} ne $that->{_local_port});
  return 1 if ($this->{_remote_port} ne $that->{_remote_port});
  return 1 if ($this->{_r_def_route} ne $that->{_r_def_route});
  return 1 if ($this->{_r_def_rt_loc} ne $that->{_r_def_rt_loc});
  return 1 if ($this->{_encrypt} ne $that->{_encrypt});
  return 1 if ($this->{_hash} ne $that->{_hash});
  return 1 if ($this->{_qos} ne $that->{_qos});
  return 1 if ($this->{_bridge} ne $that->{_bridge});
  return 1 if ($this->{_bridgecost} ne $that->{_bridgecost});
  return 1 if ($this->{_bridgeprio} ne $that->{_bridgeprio});
  return 1 if ($this->{_disable} ne $that->{_disable});
  return 1 if (listsDiff($this->{_name_server}, $that->{_name_server}));
  return 1 if (listsDiff($this->{_push_route}, $that->{_push_route}));
  return 1 if ($this->{_server_mclients} ne $that->{_server_mclients});
  return 1 if ($this->{_pam_login} ne $that->{_pam_login});
  return 1 if ($this->{_pam_username} ne $that->{_pam_username});
  return 1 if ($this->{_pam_password} ne $that->{_pam_password});
  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  # suppress uninitialized warnings here
  no warnings qw(uninitialized);

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_local_addr} ne $that->{_local_addr});
  return 1 if ($this->{_local_host} ne $that->{_local_host});
  return 1 if ($this->{_remote_addr} ne $that->{_remote_addr});
  return 1 if (listsDiff($this->{_remote_host}, $that->{_remote_host}));
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
  return 1 if (doublePairDiff($this->{_client_subnet},
                             $that->{_client_subnet}));
  return 1 if ($this->{_topo} ne $that->{_topo});
  return 1 if ($this->{_proto} ne $that->{_proto});
  return 1 if ($this->{_local_port} ne $that->{_local_port});
  return 1 if ($this->{_remote_port} ne $that->{_remote_port});
  return 1 if ($this->{_r_def_route} ne $that->{_r_def_route});
  return 1 if ($this->{_r_def_rt_loc} ne $that->{_r_def_rt_loc});
  return 1 if ($this->{_encrypt} ne $that->{_encrypt});
  return 1 if ($this->{_hash} ne $that->{_hash});
  return 1 if ($this->{_qos} ne $that->{_qos});
  return 1 if ($this->{_bridge} ne $that->{_bridge});
  return 1 if ($this->{_bridgecost} ne $that->{_bridgecost});
  return 1 if ($this->{_bridgeprio} ne $that->{_bridgeprio});
  return 1 if ($this->{_disable} ne $that->{_disable});
  return 1 if ($this->{_description} ne $that->{_description});
  return 1 if (listsDiff($this->{_name_server}, $that->{_name_server}));
  return 1 if (listsDiff($this->{_push_route}, $that->{_push_route}));
  return 1 if (doublePairDiff($this->{_client_route}, $that->{_client_route}));
  return 1 if ($this->{_server_mclients} ne $that->{_server_mclients});
  return 1 if ($this->{_pam_login} ne $that->{_pam_login});
  return 1 if ($this->{_pam_username} ne $that->{_pam_username});
  return 1 if ($this->{_pam_password} ne $that->{_pam_password});
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

sub checkHeader {
 my ($header, $file) = @_; 
 my @hdrs; 
 if (! -r $file || !open(FP, $file)){
  return 1;
 }
 else { 
   @hdrs = grep { /^$header$/ } <FP>;
   close(FP);
   if (scalar(@hdrs) == 1) 
   { return 0; } 
   else
   { return 1; } 
 }
}

sub get_command {
  my ($self) = @_;
  my $cmd = "/usr/sbin/openvpn --daemon --verb 3 --writepid /var/run/openvpn-$self->{_intf}.pid";
  if ($self->{_pam_login}) {
     return (undef, 'Can specify "require-pam-login" in server mode only')
      if ($self->{_mode} ne 'server');
     $cmd .= " --plugin /usr/lib/openvpn/openvpn-auth-pam.so login";
  } 
  if ( $self->{_disable} ) { return ('disable', undef); }

  # status
  $cmd .= " --status $status_dir/$self->{_intf}.status $status_itvl";
 
  # interface
  my $type = 'tun';
  if ( $self->{_bridge} ) { $type = 'tap'; }
  else { $type = 'tun'; }
  $cmd .= " --dev-type $type --dev $self->{_intf}";

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
  if (!$client && !$server && !$self->{_bridge}) {
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
                   . 'client-server or bridge mode')
      if (defined($self->{_local_addr}) || defined($self->{_remote_addr}));
  }

   # local host
   if (defined($self->{_local_host})) {
    # check if this IP is present on any of the interfaces on system
    use Vyatta::Misc;
    my @interface_ips = Vyatta::Misc::getInterfacesIPadresses("all");
    my $is_there = 0;
    foreach my $elt (@interface_ips) {
     # prune elt to make it an IP address without mask
     my @just_ip = split('/', $elt);
     if ($self->{_local_host} eq $just_ip[0]) {
      $is_there = 1;
      last;
     }
    }
    if ($is_there == 1) {
     $cmd .= " --local $self->{_local_host}";
    } else {
     return (undef,
"No interface on system with specified local-host IP address $self->{_local_host}");
    }
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
      if (!Vyatta::TypeChecker::validateType('ipv4', $rhost, 1)) {
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

  # qos
  $cmd .= " --up /opt/vyatta/sbin/vyatta-qos-up" if ($self->{_qos});

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
    my $hdrs = checkHeader("-----BEGIN CERTIFICATE-----",$self->{_tls_ca}); 
    return (undef, "Specified ca-cert-file \"$self->{_tls_ca}\" is not valid")
      if ($hdrs != 0); 
    $cmd .= " --ca $self->{_tls_ca}";
    
    return (undef, 'Must specify "tls cert-file"')
      if (!defined($self->{_tls_cert}));
    $hdrs = checkHeader("-----BEGIN CERTIFICATE-----", $self->{_tls_cert});
    return (undef, "Specified cert-file \"$self->{_tls_cert}\" is not valid")
      if ($hdrs != 0); 
    $cmd .= " --cert $self->{_tls_cert}";
    
    return (undef, 'Must specify "tls key-file"')
      if (!defined($self->{_tls_key}));
    $hdrs = checkHeader("-----BEGIN RSA PRIVATE KEY-----", $self->{_tls_key});
    return (undef, "Specified key-file \"$self->{_tls_key}\" is not valid")
      if ($hdrs != 0); 
    $cmd .= " --key $self->{_tls_key}";
   
    if (defined($self->{_tls_crl})) {
      $hdrs = checkHeader("-----BEGIN X509 CRL-----", $self->{_tls_crl});
      return (undef, "Specified crl-file \"$self->{_tls_crl}\" is not valid")
        if ($hdrs != 0); 
      $cmd .= " --crl-verify $self->{_tls_crl}";
    }

    if (!defined($self->{_tls_dh})) {
      return (undef, 'Must specify "tls dh-file" in server mode')
        if ($server);
    } else {
      return (undef, 'Cannot specify "tls dh-file" in client mode')
        if ($client);
      $hdrs = checkHeader("-----BEGIN DH PARAMETERS-----",$self->{_tls_dh});
      return (undef, "Specified dh-file \"$self->{_tls_dh}\" is not valid")
        if ($hdrs != 0);
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
    my $err = "Specified shared-secret-key-file \"$self->{_secret_file}\" "
              . 'is not valid';
    return (undef, $err) if (! -r $self->{_secret_file}
                             || !open(SF, "<$self->{_secret_file}"));
    my @hdrs = grep { /^-----BEGIN OpenVPN Static key V1-----$/ } <SF>;
    return (undef, $err) if (scalar(@hdrs) != 1);
    # we can further validate the secret file
    $cmd .= " --secret $self->{_secret_file}";
  }

  # username & password for pam authentication
  if (defined($self->{_pam_username}) && defined($self->{_pam_password})) {
    return (undef, 'Can specify "username/password" in client mode only')
      if ($self->{_mode} ne 'client');
    system("mkdir -p $upfile_dir ; rm -f $upfile_dir/*");
      return (undef, 'Cannot generate username/password file for authentication') if ($? >> 8);
    system("echo \"$self->{_pam_username}\n$self->{_pam_password}\" >> $upfile_dir/up");
      return (undef, 'Cannot generate username/password file')
      if ($? >> 8);
    
   $cmd .= " --auth-user-pass $upfile_dir/up";
  }
  elsif (defined($self->{_pam_username}) || defined($self->{_pam_password})) {
   return (undef, 'Need to specify username/password pair');
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
  
  if (scalar(@{$self->{_name_server}}) > 0) { 
   for my $nserver (@{$self->{_name_server}}) {
     if (!Vyatta::TypeChecker::validateType('ipv4', $nserver, 1)) {
       if (!($nserver =~ /^[0-9.]+$/)) {
         return (undef, 'Must specify IP address for "name-server"');
       }
     }
    $cmd .= " --push dhcp-option DNS $nserver";
   }
  }
 
  if (scalar(@{$self->{_push_route}}) > 0) { 
   for my $proute (@{$self->{_push_route}}) {
    my $s = new NetAddr::IP "$proute";
    my $n = $s->addr();
    my $m = $s->mask();
    $cmd .= " --push route $n $m";
   }
  } 

 if (defined ($self->{_server_mclients})) {
    return (undef, 'Maximum client connection cannot be set to 0 or less') 
     if ($self->{_server_mclients} <= 0);
    $cmd .= " --max-clients $self->{_server_mclients}"; 
 }
   return (undef, 'Must specify "server subnet" option in server mode')
      if (!defined($self->{_server_def}));
    my $s = new NetAddr::IP "$self->{_server_subnet}";
    my $n = $s->addr();
    my $m = $s->mask();
    $cmd .= " --server $n $m";

    # per-client config specified. write them out.
    system("mkdir -p $ccd_dir ; rm -f $ccd_dir/*");
    return (undef, 'Cannot generate per-client configurations') if ($? >> 8);
    if (scalar(@{$self->{_client_ip}}) > 0
        || scalar(@{$self->{_client_subnet}}) > 0
        || scalar(@{$self->{_client_route}}) > 0) {
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
        my $i=1;
        while (${$ref}[$i]) { 
         my $cs = new NetAddr::IP "${$ref}[$i]";
         my $cn = $cs->addr();
         my $cm = $cs->mask();
         system("echo \"iroute $cn $cm\" >> $ccd_dir/$client");
         return (undef, 'Cannot generate per-client configurations')
          if ($? >> 8);
         $i += 1;
        }
      }
      for my $ref (@{$self->{_client_route}}) {
        my $client = ${$ref}[0];
        my $i=1;
        while (${$ref}[$i]) { 
         my $cs = new NetAddr::IP "${$ref}[$i]";
         my $cn = $cs->addr();
         my $cm = $cs->mask();
         system("echo push \"route $cn $cm\" >> $ccd_dir/$client");
         return (undef, 'Cannot generate per-client configurations')
          if ($? >> 8);
         $i += 1;
        }
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

#STATIC function
sub wait_until_dead {
  my ($intf,$kill_repeatedly) = @_;
  my ($i, $done) = (0, 0);
  my $PGREP = "pgrep -f '^/usr/sbin/openvpn .* --dev " . $intf . " --'";
  
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

#STATIC function
sub kill_daemon {
    my ($intf) = @_;
    my $PGREP = "pgrep -f '^/usr/sbin/openvpn .* --dev " . $intf . " --'";
    
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
    return if (wait_until_dead($intf,0));
    
    # still alive. kill forcefully.
    system("kill -9 `$PGREP` >&/dev/null");
    if (!wait_until_dead($intf,1)) {
	# undead
	print STDERR "OpenVPN configuration error: Failed to stop tunnel.\n";
	exit 1;
    }
}

sub removeBridge {
    my ($self) = @_;
    if ( $self->{_bridge} ) {
      my $tap = `ip link show $self->{_intf}`;

      if ($tap =~ /ether/ ) {
         my $cmd = "sudo brctl delif $self->{_bridge} $self->{_intf}";
         system($cmd) == 0
            or print "Error removing $self->{_intf} from bridge $self->{_bridge}\n";
         $cmd = "sudo /usr/sbin/openvpn --rmtun --dev-type tap --dev $self->{_intf} > /dev/null";
         system($cmd) == 0
            or die "Error deleting tap interface $self->{_intf}\n";
      }
   }
}

sub setupBridge {
    my ($self) = @_;
    if ( $self->{_bridge} ) {
       my $cmd = "sudo /usr/sbin/openvpn --mktun --dev-type tap --dev $self->{_intf} > /dev/null";
       system($cmd) == 0 
          or die "Error creating tap interface $self->{_intf}\n";
       $cmd = "ip link set $self->{_intf} up promisc on";
       system($cmd) == 0
          or die "Error setting parameters for tap interface $self->{_intf}\n";
       $cmd = "sudo brctl addif $self->{_bridge} $self->{_intf}";
       system($cmd) == 0
          or die "Error adding interface $self->{_intf} to bridge $self->{_bridge}\n";
    }
}

sub configureBridge {
    my ($self) = @_;
    
    if ( $self->{_bridge} ) {
       # Set port cost
       my $cmd = "sudo brctl setpathcost $self->{_bridge} $self->{_intf}"; 
       if ( $self->{_bridgecost} ) { $cmd .= " $self->{_bridgecost}"; }
       else { $cmd .= " 0"; }
       system ($cmd) == 0
          or die "Error setting bridge cost for $self->{_intf}\n";
    
       # Set port priority
       $cmd = "sudo brctl setportprio $self->{_bridge} $self->{_intf}";
       if ( $self->{_bridgeprio} ) { $cmd .= " $self->{_bridgeprio}"; }
       else { $cmd .= " 0"; }
       system ($cmd) == 0
          or die "Error setting bridge priority for $self->{_intf}\n";
   }
}

1;
