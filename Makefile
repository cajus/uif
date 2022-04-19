# uif-1.1.x Installer Makefile

#  Copyright (C) 2002-2015, Cajus Pollmeier <pollmeier@gonicus.de>
#  Copyright (C) 2002-2015, Jörg Platte <jplatte@gmx.net>
#  Copyright (C) 2013-2022, Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

# Change here to install to different location
DESTDIR ?=
PREFIX  ?= /usr/local

VERSION = `cat VERSION | head -1`

all:

install:
	@echo "Installing uif script..."

	@# create directories
	install -o root -g root -m 700 -d $(DESTDIR)/etc/uif
	install -o root -g root -m 700 -d $(DESTDIR)/etc/uif/uif.conf.d
	install -o root -g root -m 700 -d $(DESTDIR)/etc/uif/uif-ipv4-networks.inc.d
	install -o root -g root -m 700 -d $(DESTDIR)/etc/uif/uif-ipv6-networks.inc.d
	install -o root -g root -m 755 -d $(DESTDIR)/etc/default
	install -o root -g root -m 755 -d $(DESTDIR)/etc/init.d
	install -o root -g root -m 755 -d $(DESTDIR)/etc/ldap/schema
	install -o root -g root -m 755 -d $(DESTDIR)$(PREFIX)/sbin
	install -o root -g root -m 755 -d $(DESTDIR)$(PREFIX)/share/doc/uif
	install -o root -g root -m 755 -d $(DESTDIR)$(PREFIX)/share/man/man8
	install -o root -g root -m 755 -d $(DESTDIR)$(PREFIX)/share/man/man5
	
	@# install files
	install -o root -g root -m 700 uif.pl $(DESTDIR)$(PREFIX)/sbin/uif
	install -o root -g root -m 600 default $(DESTDIR)/etc/default/uif
	install -o root -g root -m 600 services $(DESTDIR)/etc/uif
	if [ ! -e $(DESTDIR)/etc/uif/uif.conf ]; then install -o root -g root -m 600 uif.conf $(DESTDIR)/etc/uif; fi
	if [ ! -e $(DESTDIR)/etc/uif/uif-ipv4-networks.inc ]; then install -o root -g root -m 600 uif-ipv4-networks.inc $(DESTDIR)/etc/uif; fi
	if [ ! -e $(DESTDIR)/etc/uif/uif-ipv6-networks.inc ]; then install -o root -g root -m 600 uif-ipv6-networks.inc $(DESTDIR)/etc/uif; fi
	install -o root -g root -m 755 uif.initscript $(DESTDIR)/etc/init.d
	mv $(DESTDIR)/etc/init.d/uif.initscript $(DESTDIR)/etc/init.d/uif
	install -o root -g root -m 644 uif.schema $(DESTDIR)/etc/ldap/schema

	@# install documentation
	install -o root -g root -m 644 docs/uif.conf.IPv4.tmpl $(DESTDIR)$(PREFIX)/share/doc/uif
	install -o root -g root -m 644 docs/uif.conf.IPv4+6.tmpl $(DESTDIR)$(PREFIX)/share/doc/uif
	install -o root -g root -m 644 docs/examples.IPv4.txt $(DESTDIR)$(PREFIX)/share/doc/uif
	install -o root -g root -m 644 uif.8 $(DESTDIR)$(PREFIX)/share/man/man8
	install -o root -g root -m 644 uif.conf.5 $(DESTDIR)$(PREFIX)/share/man/man5
