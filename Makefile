# uif-1.1.x Installer Makefile
#
# Cajus Pollmeier <pollmeier@gonicus.de>
# Jörg Platte     <joerg.platte@gmx.de>
# Mike Gabriel    <mike.gabriel@das-netzwerkteam.de>

# Change here to install to different location
PREFIX = ${DESTDIR}
VERS = `sed -n "s/[^ ]* (\([0-9.]*\)-[0-9]*).*/\1/p" debian/changelog | head -1`

install:
	@echo "Installing uif script..."

	@# create directories
	install -o root -g root -m 700 -d ${PREFIX}/etc/uif
	install -o root -g root -m 755 -d ${PREFIX}/etc/default
	install -o root -g root -m 755 -d ${PREFIX}/etc/init.d
	install -o root -g root -m 755 -d ${PREFIX}/etc/ldap/schema
	install -o root -g root -m 755 -d ${PREFIX}/usr/sbin
	install -o root -g root -m 755 -d ${PREFIX}/usr/share/doc/uif
	install -o root -g root -m 755 -d ${PREFIX}/usr/share/man/man8
	install -o root -g root -m 755 -d ${PREFIX}/usr/share/man/man5
	
	@# install files
	install -o root -g root -m 700 uif.pl ${PREFIX}/usr/sbin/uif
	install -o root -g root -m 600 default ${PREFIX}/etc/default/uif
	install -o root -g root -m 600 services ${PREFIX}/etc/uif
	if [ ! -e ${PREFIX}/etc/uif/uif.conf ]; then install -o root -g root -m 600 uif.conf ${PREFIX}/etc/uif; fi
	if [ ! -e ${PREFIX}/etc/uif/uif-ipv4-networks.inc ]; then install -o root -g root -m 600 uif-ipv4-networks.inc ${PREFIX}/etc/uif; fi
	if [ ! -e ${PREFIX}/etc/uif/uif-ipv6-networks.inc ]; then install -o root -g root -m 600 uif-ipv6-networks.inc ${PREFIX}/etc/uif; fi
	install -o root -g root -m 755 uif ${PREFIX}/etc/init.d
	install -o root -g root -m 644 uif.schema ${PREFIX}/etc/ldap/schema

	@# install documentation
	install -o root -g root -m 644 docs/uif.conf.IPv4.tmpl ${PREFIX}/usr/share/doc/uif
	install -o root -g root -m 644 docs/uif.conf.IPv4+6.tmpl ${PREFIX}/usr/share/doc/uif
	install -o root -g root -m 644 docs/examples.IPv4.txt ${PREFIX}/usr/share/doc/uif
	install -o root -g root -m 644 uif.8 ${PREFIX}/usr/share/man/man8
	install -o root -g root -m 644 uif.conf.5 ${PREFIX}/usr/share/man/man5
