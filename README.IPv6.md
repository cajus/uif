# IPv6 support for UIF 1.1.8

Starting with version 1.1.0 UIF is able to handle IPv6 iptables as well
as IPv4 iptables. The IPv6 support was originally provided by Alex Owen
via a patch sent to the Debian bug tracker. Awesome thanks to Alex for
this initial piece of work!!!

With IPv6 support added, UIF can now also produce IPv6 firewall rules.
The init script can, by setting IPV6MODE=1 in /etc/default/uif, be made
to install the IPv4 rules from /etc/uif/uif.conf and the IPv6 rules from
/etc/uif/uif6.conf.

Judicious use of the include and include4 and include6 sections of the
config files can mean that the ipv6 and ipv4 rules can be identical
except for including a network section with IPv4 definitions and IPv6
definitions respectivly.

## Configuration Examples

The file uif6.conf can be a sym-link to uif.conf or contain:

```
--uif6.conf--
include {
    "/etc/uif/uif.conf"
}
-------------
```

The file uif.conf can then be used for a single set of rules but can include
different network definitions as needed:

```
--uif.conf--
#include common services 
include {
    "/etc/uif/services"
}
# in IPv4 mode include IPv4 network definitions
include4 {
    "/etc/uif/networks4"
}
#In IPv6 mode include IPv6 network defnintions
include6 {
    "/etc/uif/networks6"
}
#common filter block for both ipv4 and ipv6 
filter {

  #Put your firewall rules here

}
------------
```


As an addition it is possible to append "(4)" or "(6)" to network names in filtering
rules (e.g.: "in+ s=trusted(4)"). This limits the application of this rule to the
specified IP protocol version only.

This can be especially helpful, if some of your network names only exist for one IP
protocol version but not for the other.

## AUTHORS

 * Alex Owen <r.alex.owen@gmail.com>, Sun, 15 Jul 2012 14:41:22 +0100
 * Mike Gabriel <mike.gabriel@das-netzwerkteam.de>, Wed, 22 Jan 2014 13:50:01 +0100
