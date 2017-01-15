# Installation Guide for UIF 1.1.8

This file contains some quick installation hints for
the UIF package.

## Download

You can get the newest version at https://github.com/cajus/uif.

## Dependencies

In order to use the script, you need iptables, ip6tables, Perl,
NetAddr::IP (>=3.0), Socket, Data::Validate::IP and optionally Net::LDAP.

## Build

Well - there's nothing to build. Just change the PREFIX on top of the
Makefile and do a "make install". If you want to start UIF during bootup
you should add the needed links in /etc/rc*. See file "uif.initscript"
for a working init script.

## Debian

The UIF package is regularly released via Debian. Use APT to retrieve
this piece of software directly from the Debian archives:

```
  # apt-get install uif
```

## Documentation

Use "man uif" and "man uif.conf" to see what's possible.
