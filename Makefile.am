cfgdir		 = $(datadir)/vyatta-cfg/templates
share_perl5dir	 = $(datarootdir)/perl5

sbin_SCRIPTS = scripts/vyatta-update-ovpn.pl
share_perl5_DATA = scripts/VyattaOVPNConfig.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)

