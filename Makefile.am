cfgdir		 = $(datadir)/vyatta-cfg/templates
opdir		 = $(datadir)/vyatta-op/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta/OpenVPN
bin_sudo_usersdir = $(bindir)/sudo-users

sbin_SCRIPTS = scripts/vyatta-update-ovpn.pl
sbin_SCRIPTS += scripts/vyatta-qos-up

share_perl5_DATA = lib/Vyatta/OpenVPN/Config.pm
bin_sudo_users_SCRIPTS = scripts/vyatta-show-ovpn.pl
bin_sudo_users_SCRIPTS = scripts/vyatta-restart-ovpn.pl

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)

