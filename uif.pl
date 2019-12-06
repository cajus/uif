#!/usr/bin/perl -w

# Copyright (C) 2002-2015 Jörg Platte <joergplatte@gmx.de>
# Copyright (C) 2002-2015 Cajus Pollmeier <pollmeier@gonicus.de>
# Copyright (C) 2013-2015 Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
# Copyright (C) 2013-2015 Alex Owen <r.alex.owen@gmail.com>
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
#
# On Debian GNU/Linux systems, a copy of the GNU General Public License may be
# found in the file /usr/share/common-licenses/GPL.

use strict;
my $LDAPENABLED = eval "use Net::LDAP; 1" ? '1' : '0';

use Getopt::Std;
use NetAddr::IP;
use Data::Validate::IP qw(is_ipv6 is_ipv4);
use Socket qw(:addrinfo SOCK_RAW AF_INET AF_INET6);

my $SignalCatched=0;

my $configfile="/etc/uif/uif.conf";
my $configfile6="/etc/uif/uif6.conf";
my $ipv6=0;

my @mapping = (	[ 'n', 'uifid', 'Name' ],
		[ 's', 'uifsource', 'Source'],
		[ 'i', 'uifindevice', 'InputInterface'],
		[ 'pi', 'uifpindevice', 'PhysicalInputInterface'],
		[ 'd', 'uifdest', 'Destination'],
		[ 'o', 'uifoutdevice', 'OutputInterface'],
		[ 'po', 'uifpoutdevice', 'PhysicalOutputInterface'],
		[ 'p', 'uifservice', 'Service'],
		[ 'm', 'uifmark', 'MarkMatch'],
		[ 'S', 'uiftranssource', 'TranslatedSource'],
		[ 'D', 'uiftransdest', 'TranslatedDestination'],
		[ 'P', 'uiftransservice', 'TranslatedService'],
		[ '',  'uiftype', 'Type'],
		[ 'f', 'uifflag', 'Flags']);

my %charstringmap;
my %ldapstringmap;
my %ldapwritemap;
my %stringcharmap;

foreach (@mapping) {
	$charstringmap{${$_}[0]}=${$_}[2];
	$stringcharmap{${$_}[2]}=${$_}[0];
	if (${$_}[0]) {
		$ldapstringmap{${$_}[1]}=${$_}[2];
	}
	$ldapwritemap{${$_}[2]}=${$_}[1];
}

sub readConfig {
	my ($configfile, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Id, $Sysconfig, $Marker) = @_;
	my @conflines;
	my @protlines;
	my $state='NONE';
	my $line;

	unless (defined($$Protocols{'OK'})) {
		$$Protocols{'OK'}=1;
		open (PROT, '/etc/protocols') || die "Can't read '/etc/protocols'\n";
		@protlines = <PROT>;
		close (PROT);

		foreach $line (@protlines) {
			if ($line =~ /^\s*(#|$)/) {
				next;
			}
			chomp($line);
			if ($line =~ /^([a-z0-9-.]+)\s+(\d+)\s+/) {
				$$Protocols{$1}=$2;
				$$Protocols{$2}=$1;
			} else {
				die "invalid line in '/etc/protocols': $line\n";
			}
		}
	}

	open (CONF, $configfile) || die "Can't read configfile '$configfile'\n";
	@conflines = <CONF>;
	close (CONF);

	foreach $line (@conflines) {
		$line =~ /^\s*(#|$)/ && next;
		chomp($line);
		if ($state eq 'NONE') {
			my $type;
			if ($line =~ /^\s*([^\s}]+)\s*{\s*$/) {
				$state="\U$1";
			} else {
				die "invalid line: $line\n";
			}
		} else {
			if ($line =~ /^\s*}\s*$/) {
				$state='NONE';
			} elsif ($state eq 'SERVICE') {
				if ($line =~ /^\s*([a-zA-Z0-9_-]+)\s+(.*)$/) {
					$$Services{$1}.="$2 ";
				} else {
					die "invalid line in section service: $line\n";
				}
			} elsif ($state eq 'INCLUDE') {
				if ($line =~ /^\s*\"(.+)\"$/) {
					my $file = $1;
					readConfig ($file, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Id, $Sysconfig);
				} else {
					die "invalid line in section include: $line\n";
				}
			} elsif ($state eq 'INCLUDE6') {
				if ($ipv6) {
					if ($line =~ /^\s*\"(.+)\"$/) {
						my $file = $1;
						readConfig ($file, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Id, $Sysconfig);
					} else {
						die "invalid line in section include6: $line\n";
					}
				}
			} elsif ($state eq 'INCLUDE4') {
				if ($ipv6) {} else {
					if ($line =~ /^\s*\"(.+)\"$/) {
						my $file = $1;
						readConfig ($file, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Id, $Sysconfig);
					} else {
						die "invalid line in section include4: $line\n";
					}
				}
			} elsif ($state eq 'NETWORK') {
				if ($line =~ /^\s*([a-zA-Z0-9_-]+)\s+(.*)$/) {
					$$Networks{$1}.="$2 ";
				} else {
					die "invalid line in section network: $line\n";
				}
			} elsif ($state eq 'INTERFACE') {
				if ($line =~ /^\s*([a-zA-Z0-9_-]+(:\d+)?)\s+(.*)$/) {
					$$Interfaces{$1}.="$3 ";
				} else {
					die "invalid line in section interface: $line\n";
				}
			} elsif ($state eq 'MARKER') {
				if ($line =~ /^\s*([a-zA-Z0-9_-]+)\s+(.*)$/) {
					$$Marker{$1}.="$2 ";
				} else {
					die "invalid line in section marker: $line\n";
				}
			} elsif ($state eq 'SYSCONFIG') {
				if ($line =~ /^\s*([a-zA-Z0-9_-]+)\s+(.*)$/) {
					$$Sysconfig{$1}=$2;
				} else {
					die "invalid line in section sysconfig: $line\n";
				}
			} elsif ($state =~ /^(FILTER|NAT|INPUT|OUTPUT|FORWARD|MASQUERADE|STATELESS)$/) {
				if ($line =~ /^\s*(\w+([-+|>]|{\w+}))\s*(.*)$/) {
					my $type = $1;
					my $parameter = $3;
					my %temphash;
					$temphash{'Type'}=$type;
					$temphash{'Rule'}=$line;
					$temphash{'Id'}=$$Id++;
					my $entry;
					foreach $entry (split(/\s+/, $parameter)) {
						$entry eq '' && next;
						if ($entry =~ /^([a-zA-Z]{1,2})=([^=]+)$/) {
							if (exists($charstringmap{$1})) {
								my $value = $2;
								$value =~ tr /,/ /;
								$temphash{$charstringmap{$1}}.="$value ";
							} else {
								die "invalid prefix: $1\n";
							}
						} else {
							die "invalid parameter: $entry\n";
						}
					}
					push (@$Rules, \%temphash);
				} else {
					die "invalid line in section filter/nat: $line\n"
				}
			} else {
				die "invalid section: \L$state\n";
			}
		}
	}
}

sub resolveHashentries {
	my ($value, $Hash, $depth) = @_;

	unless (defined($depth)) {
		$depth=1;
	} elsif ($depth++ > 50) {
		die "possible loop in configfile: $value\n";
	}

	my $newvalue;
	my $entry;
	foreach $entry (split (/\s+/, $value)) {
		$entry eq '' && next;
		if (exists($$Hash{$entry})) {
			$newvalue.=" ".resolveHashentries($$Hash{$entry}, $Hash, $depth);
		} else {
			$newvalue.=" ".$entry;
		}
	}
	return $newvalue;
}

sub expandRange {
	my ($range, $multi) = @_;
	if (@$range != 0) {
		unless (@$multi == 0 && @$range==1) {
			my %rangehash;
			my @rangearray;
			my $entry;
			foreach $entry (@$range) {
				$entry =~ /(\d+):(\d+)/;
				my $range=$2-$1+1;
				if (exists($rangehash{$range})) {
					push (@{$rangehash{$range}}, $1);
				} else {
					$rangehash{$range}=[$1];
				}
				push (@rangearray, $range);
			}

			@rangearray=sort {$a <=> $b} (@rangearray);

			my $again=1;
			my $last=15;
			while ($again) {
				$again=0;
				while (@rangearray) {
					my $range=$rangearray[0];
					if (@$multi+$range<=$last) {
						my $first=shift(@{$rangehash{$range}});
						my $port;
						for ($port=$first+$range-1; $port>=$first; $port--) {
							push (@$multi, $port);
						}
						shift (@rangearray);
					} else {
						last;
					}
				}
				if (@rangearray>1) {
					$last+=15;
					if (@$multi+$rangearray[0]+$rangearray[1]<=$last) {
						$again=1;
					}
				}
			}
			my @temprange;
			foreach $range (@rangearray) {
				foreach (@{$rangehash{$range}}) {
					my $last=$_+$range-1;
					push(@temprange, "$_:$last");
				}
			}
			@$range=@temprange;
		}
	}
}

sub simplifyNetworks {
	my (@networks) = @_;
	my @netobjects;
	my $netref;
	my %macs;
	my $mac;
	my $network;
	if (@networks) {
		my $ip;
		my $no_macs=1;
		foreach (@networks) {

			my $netaddr = '';
			my $network = '';
			my $macaddr = '';
			if ( ($_ =~ /(^[^\/]+)\/([^\/^=]+)$/) || (($ipv6) && is_ipv6($_)) || ((!$ipv6) && is_ipv4($_)) ) {

				if ($ipv6) {
					$ip=NetAddr::IP->new6($_) || die "not a valid address or network: $_\n";
				} else {
					$ip=NetAddr::IP->new($_) || die "not a valid address or network: $_\n";
				}
				push(@netobjects, $ip);

			}
			elsif ( $_ =~ /(^[^=]+)=([^=]+)$/ ) {

				$netaddr = $1;
				$macaddr = $2;
				if ($netaddr =~ /(^[^\/]+)\/([^\/]+)$/) {
					$network = $1;
					# FIXME: netmask = $2; TODO: validate netmask
				} else {
					$network = $netaddr;
				}

				if ( (($ipv6) && is_ipv6($network)) || ((!$ipv6) && is_ipv4($network)) ) {

					if ($ipv6) {
						$ip=NetAddr::IP->new6($netaddr) || die "not a valid address or network: $netaddr\n";
					} else {
						$ip=NetAddr::IP->new($netaddr) || die "not a valid address or network: $netaddr\n";
					}
					if (!exists($macs{$ip})) {
						$macs{$ip}=[];
					}
					$no_macs = 0;
					push (@{$macs{$ip}}, $macaddr);
					push (@netobjects, $ip);

				} else {

					die "Cannot use <dns-name>=<mac-addr> syntax, must be <network-or-ip-addr>=<mac-addr>"

				}
			}
			else {

				# resolv "address" that actually is a DNS host name, not an IP address...
				my $err;
				my @res;

				if ($ipv6) {
					( $err, @res ) = getaddrinfo( $_, "", { socktype => SOCK_RAW, family => AF_INET6 } );
				} else {
					( $err, @res ) = getaddrinfo( $_, "", { socktype => SOCK_RAW, family => AF_INET } );
				}
				die "Cannot getaddrinfo for name '".$_."'- ".$err if $err;

				while ( my $ai = shift @res ) {

					my ( $err, $ipaddr ) = getnameinfo( $ai->{addr}, NI_NUMERICHOST, NIx_NOSERV );
					die "Cannot getnameinfo - $err" if $err;

					if ($ipv6) {
						$ip=NetAddr::IP->new6($ipaddr) || die "not a valid address: $ipaddr\n";
					} else {
						$ip=NetAddr::IP->new($ipaddr) || die "not a valid address: $ipaddr\n";
					}

					push (@netobjects, $ip);
				}
			}

		}

		# if we don't handle individual MAC addresses on any of the networks, then
		# we can compact the list of networks
		if ($no_macs == 1) {
			@netobjects = NetAddr::IP::Compact(@netobjects);
		}

		@networks=();
		foreach $network (@netobjects) {
			if (exists($macs{$network})) {
				foreach $mac (@{$macs{$network}}) {
					push (@networks, $network."=".$mac);
				}
			}
			else {
				push (@networks, $network);
			}
		}
	}
	return (@networks);
}

sub checkLimit {
	my ($limit) = @_;
	if ($limit =~/^\d+(\/second|\/minute|\/hour|\/day|)$/) {
		return 1;
	} else {
		return 0;
	}
}

sub validateSysconfig {
	my ($Sysconfig) = @_;

	my $syskey;
	foreach $syskey (keys (%$Sysconfig)) {
		if ("\L$syskey" eq "loglevel") {
			my $level=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$level =~ s/\s+//g;
			if ($level =~/^(debug|info|notice|warning|err|crit|alert|emerg)$/) {
				$$Sysconfig{'LogLevel'}=$level;
			} else {
				die "unknown loglevel: $level\n";
			}
		} elsif ("\L$syskey" eq "logprefix") {
			my $prefix=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$$Sysconfig{'LogPrefix'}=$prefix;
		} elsif ("\L$syskey" eq "loglimit") {
			my $limit=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$limit =~ s/\s+//g;
			if (checkLimit $limit) {
				$$Sysconfig{'LogLimit'}=$limit;
			} else {
				die "unknown loglimit: $limit:\n";
			}
		} elsif ("\L$syskey" eq "logburst") {
			my $burst=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$burst =~ s/\s+//g;
			if ($burst =~/^\d+$/) {
				$$Sysconfig{'LogBurst'}=$burst;
			} else {
				die "unknown logburst: $burst\n";
			}
		} elsif ("\L$syskey" eq "limit") {
			my $limit=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$limit =~ s/\s+//g;
			if (checkLimit $limit) {
				$$Sysconfig{'Limit'}=$limit;
			} else {
				die "unknown limit: $limit:\n";
			}
		} elsif ("\L$syskey" eq "burst") {
			my $burst=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$burst =~ s/\s+//g;
			if ($burst =~/^\d+$/) {
				$$Sysconfig{'Burst'}=$burst;
			} else {
				die "unknown burst: $burst\n";
			}
		} elsif ("\L$syskey" eq "accountprefix") {
			my $prefix=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$prefix =~ s/\s+//g;
			if ($prefix =~/^\w+$/) {
				$$Sysconfig{'AccountPrefix'}=$prefix;
			} else {
				die "invalid account prefix: $prefix\n";
			}
		} elsif ("\L$syskey" eq "filtercommand") {
			my $filter_command=$$Sysconfig{$syskey};
			delete $$Sysconfig{$syskey};
			$filter_command =~ s/\s+//g;
			if ($filter_command eq 'nft') {
				$$Sysconfig{'filtercommand'} = 'nft';
			} elsif ($filter_command eq 'iptables') {
				$$Sysconfig{'filtercommand'} = 'iptables';
			} elsif ($filter_command eq 'iptables-nft') {
				$$Sysconfig{'filtercommand'} = 'iptables-nft';
			} elsif ($filter_command eq 'iptables-legacy') {
				$$Sysconfig{'filtercommand'} = 'iptables-legacy';
			} else {
				die "invalid packet filter command, use 'nft', 'iptables', 'iptables-nft' or 'iptables-legacy'";
			}
		} else {
			die "unknown sysconfig parameter: $syskey\n";
		}
	}
}

sub toRange {
	my ($range, $proto, $rule) = @_;

	if ($range =~ /^(\d*)(|:(\d*))$/) {
		if ($1 && $3) {
			return "$1:$3";
		} elsif ($1 && $2) {
			return "$1:65535";
		} elsif ($2 && $3) {
			return "0:$3";
		} elsif ($1) {
			return "$1:$1";
		} else {
			return "0:65535";
		}
	} else {
		die "invalid $proto service: $range:\n$rule\n";
	}
}

sub validateData {
	my ($Networks, $Services, $Interfaces, $Protocols, $Rules, $Sysconfig, $Marker) = @_;

	validateSysconfig $Sysconfig;

	my $key;
	foreach $key (keys (%$Networks)) {
		$$Networks{$key} = resolveHashentries($$Networks{$key}, $Networks);
	}
	foreach $key (keys (%$Services)) {
		$$Services{$key} = resolveHashentries($$Services{$key}, $Services);
	}
	foreach $key (keys (%$Interfaces)) {
		$$Interfaces{$key} = resolveHashentries($$Interfaces{$key}, $Interfaces);
	}
	foreach $key (keys (%$Interfaces)) {
		if (!($$Interfaces{$key} =~ /^[a-zA-Z0-9+ ]+(:\d+)?$/)) {
			die "invalid character in interface definition: $$Interfaces{$key}\n";
		}
	}

	foreach $key (keys (%$Marker)) {
		$$Marker{$key} = resolveHashentries($$Marker{$key}, $Marker);
	}

## marken auf plausibilität prüfen

	my $rule;
	foreach $rule (@$Rules) {
		if (exists($$rule{'TranslatedSource'}) && exists($$rule{'TranslatedDestination'})) {
			die "can't modify source and destination address in one rule:\n$$rule{'Rule'}\n";
		}
		my $ruletype=$$rule{'Type'};
		if ($ruletype =~ /^\s*(masq|snat|dnat|nat)(\+|-)$/) {
			my $type = $1;
			my $action = $2;
			$$rule{'Table'}='nat';
			if ($type eq 'masq') {
				if ($ipv6) {
					$$rule{'Type'}='IGNORE-IPV6-POSTROUTING';
				} else {
					$$rule{'Type'}='POSTROUTING';
				}
				$$rule{'Action'}='MASQUERADE';
			} elsif ($type =~ /^(s|d|)nat$/) {
				if (exists($$rule{'TranslatedSource'})) {
					if ($ipv6) {
						$$rule{'Type'}='IGNORE-IPV6-POSTROUTING';
					} else {
						$$rule{'Type'}='POSTROUTING';
					}
					$$rule{'Action'}='SNAT';
				} elsif (exists($$rule{'TranslatedDestination'})) {
					if ($ipv6) {
						$$rule{'Type'}='IGNORE-IPV6-PREROUTING';
					} else {
						$$rule{'Type'}='PREROUTING';
					}
					$$rule{'Action'}='DNAT';
				} else {
					die "nat rule without address translation makes no sense:\n$$rule{'Rule'}\n";
				}
			}
			if ($action eq '-') {
				$$rule{'Action'}='DROP';
			}
		} elsif ($ruletype =~ /^\s*(in|out|fw|slin|slout|slfw)(\+|-|\||>|{\w+})$/) {
			my $type = $1;
			my $action = $2;
			$$rule{'Table'}='filter';
			if ($type eq 'fw') {
				$$rule{'Type'}='FORWARD';
			} elsif ($type eq 'in') {
				$$rule{'Type'}='INPUT';
			} elsif ($type eq 'out') {
				$$rule{'Type'}='OUTPUT';
			} elsif ($type eq 'slfw') {
				$$rule{'Type'}='STATELESSFORWARD';
			} elsif ($type eq 'slin') {
				$$rule{'Type'}='STATELESSINPUT';
			} else {
				$$rule{'Type'}='STATELESSOUTPUT';
			}
			if ($action eq '+') {
				$$rule{'Action'}='ACCEPT';
			} elsif ($action eq '-') {
				$$rule{'Action'}='DROP';
			} elsif ($action eq '|') {
				if ($$rule{'Type'} =~ /OUTPUT/) {
					die "can't use mirror in OUTPUT chain\n";
				} else {
					$$rule{'Action'}='MIRROR';
				}
			} elsif ($action =~ /^{(\w+)}$/) {
				my $marker=$1;
				$$rule{'Action'}='MARK';
				$$rule{'Table'}='mangle';
				if (exists($$Marker{$marker})) {
					my @dummy = split(/\s+/, $$Marker{$marker});
					if ($#dummy == 1) {
						$$rule{'Mark'}=$$Marker{$marker};
					} else {
						die "can't mark packet with multiple mark values: $marker\n$$rule{'Rule'}\n";
					}
				} else {
					die "invalid mark identifier: $marker\n$$rule{'Rule'}\n";
				}
			} else {
				if ($$rule{'Type'} =~ /INPUT/) {
					die "can't use TCPMSS in INPUT chain\n";
				} else {
					$$rule{'Action'}='TCPMSS';
				}
			}
			if (exists($$rule{'TranslatedSource'}) || exists($$rule{'TranslatedDestination'}) || exists($$rule{'TranslatedService'})) {
				die "you can modify source or destination address only in nat rules:\n$$rule{'Rule'}\n";
			}
		} else {
			die "unknown ruletype:\n$$rule{'Rule'}\n";
		}
		my $hashentry;
		foreach $hashentry (qw(Source Destination TranslatedSource TranslatedDestination)) {
			my @simplenetwork;
			if (exists($$rule{$hashentry})) {
				my $position;
				foreach $position (split (/\s+/, $$rule{$hashentry})) {
					$position eq '' && next;
					$position =~ /^(!{0,1})(.*)/;
					if ($1) {
						$$rule{"${hashentry}-not"} = 1;
					}
					$position=$2;

					# support IPv4-only/IPv6-only rules
					if ($position =~ /^.*\((.+)\)$/) {
						my $only_proto = $1;
						$position =~ s/\((.+)\)$//;
						if (($ipv6) && ($only_proto eq "4")) {
							print STDERR "IPv6 setup: Skipping IPv4-only rule for network \"$position\"\n";
							$$rule{'Type'} = 'IGNORE-IPV4-ONLY';
							next;
						} elsif ((! $ipv6) && ($only_proto eq "6")) {
							print STDERR "IPv4 setup: Skipping IPv6-only rule for network \"$position\"\n";
							$$rule{'Type'} = 'IGNORE-IPV6-ONLY';
							next;
						}
					}

					if ($$rule{'Type'} =~ /^IGNORE\-IPV6\-.*$/) {
						next;
					}

					if (exists($$Networks{$position})) {
						my $network;
						foreach $network (split (/\s+/, $$Networks{$position})) {
							$network eq '' && next;
							push (@simplenetwork, $network);
						}
					} else {
						die "invalid network name: $position\n$$rule{'Rule'}\n";
					}
				}
				@simplenetwork = simplifyNetworks (@simplenetwork);

				my $network;
				for $network (@simplenetwork) {
					if  ( ( $network =~ /(^[^=]+)=([^=]+)$/ ) && ( ! ( $hashentry =~ /^.*Source$/ ) ) ) {
						die "MAC address sources don't make sense on destination networks";
					}
					if  ( ( $network =~ /(^[^=]+)=([^=]+)$/ ) && ( $$rule{'Type'} eq 'OUTPUT' ) ) {
						die "MAC address sources don't make sense for outward bound rules";
					}
				}

				$$rule{$hashentry} = \@simplenetwork;

			}
		}
		foreach (qw(TranslatedSource TranslatedDestination)) {
			if (exists($$rule{$_}) && @{$$rule{$_}}>1) {
				die "you can specify only one source or destination network as nat target:\n$$rule{'Rule'}\n";
			}
			if (exists($$rule{"$_-not"})) {
				die "inverting nat destinations is not possible\n$$rule{'Rule'}\n";
			}
		}

		foreach (qw(Source Destination)) {
			if (exists($$rule{"${_}-not"}) && @{$$rule{$_}}>1) {
				die "you can specify only one source or destination network with not statement:\n$$rule{'Rule'}\n";
			}
		}

		if (exists($$rule{'MarkMatch'})) {
			my $mark;
			my @array;
			foreach $mark (split (/\s+/, $$rule{'MarkMatch'})) {
				$mark eq '' && next;
				foreach (split(/\s+/, $$Marker{$mark})) {
					$_ eq '' && next;
					push (@array, $_);
				}
			}
			$$rule{'MarkMatch'}=\@array;
		}
		foreach $hashentry (qw(InputInterface OutputInterface PhysicalInputInterface PhysicalOutputInterface)) {
			if (exists($$rule{$hashentry})) {
				if (($hashentry eq 'InputInterface' || $hashentry eq 'PhysicalInputInterface') && $$rule{'Type'} =~ /(OUTPUT|POSTROUTING)/) {
					die "can't use input interface in output rule:\n$$rule{'Rule'}\n";
				} elsif (($hashentry eq 'OutputInterface' || $hashentry eq 'PhysicalOutputInterface') && $$rule{'Type'} =~ /(INPUT|PREROUTING)/) {
					die "can't use output interface in input rule:\n$$rule{'Rule'}\n";
				}
				my $position;
				my %interfacehash;
				foreach $position (split (/\s+/, $$rule{$hashentry})) {
					$position eq '' && next;
					$position =~ /^(!{0,1})(.*)/;
					if ($1) {
						$$rule{"${hashentry}-not"} = 1;
					}
					$position=$2;
					if (exists($$Interfaces{$position})) {
						my $interface;
						foreach $interface (split (/\s+/, $$Interfaces{$position})) {
							$interface eq '' && next;
							$interfacehash{$interface}=1;
						}
					} else {
						die "invalid interface entry: $position\n";
					}
				}
				my @array = keys (%interfacehash);
				$$rule{$hashentry} = \@array;
			}
			if (exists($$rule{"${hashentry}-not"}) && @{$$rule{$hashentry}}>1) {
				die "you can specify only one input or output interface with not statement:\n$$rule{'Rule'}\n";
			}
		}

		my $serviceentry;
		my $servicecounter=0;
		foreach $serviceentry (qw(Service TranslatedService)) {
			$servicecounter=0;
			if (exists($$rule{$serviceentry})) {
				my $serviceprefix='';
				if ($serviceentry eq 'TranslatedService') {
					$serviceprefix='Translated';
				}
				my @newservice;
				my $position;
				my %protocols;
				foreach $position (split (/\s+/, $$rule{$serviceentry})) {
					$position eq '' && next;
					$position =~ /^(!{0,1})(.*)/;
					if ($1) {
						if ($serviceprefix) {
							die "can't use not in nat destination service description: $position\n$$rule{'Rule'}\n";
						}
						$$rule{"Service-not"}=1;
					}
					$position=$2;
					if (exists($$Services{$position})) {
						my $service;
						foreach $service (split (/\s+/, $$Services{$position})) {
							$service eq '' && next;
							if ($service =~ /^([\w-]+)\((.*)\)$/) {
								my $proto=$1;
								my $param=$2;
								if ($param eq '') {
									$param='all';
								}
								if (exists($$Protocols{$proto})) {
									if ($proto =~ /^\d+$/) {
										$proto = $$Protocols{$proto};
									}
								} else {
									die "unknown protocol: $service:\n$$rule{'Rule'}\n";
								}
								$protocols{"$serviceprefix$proto"}.=" $param";
							} else {
								die "invalid service entry: $service:\n$$rule{'Rule'}\n";
							}
						}
					} else {
						die "invalid service entry: $position\n";
					}
				}
				delete $$rule{$serviceentry};
				my $proto;
				foreach $proto (qw(udp tcp)) {
					if (exists($protocols{"$serviceprefix$proto"})) {
						my @multisource;
						my @multidestination;
						my @sourcerange;
						my @destinationrange;
						my @sourcedestination;
						my %other;
						my $service;
						foreach $service (split (/\s+/, $protocols{"$serviceprefix$proto"})) {
							$service eq '' && next;
							if ($service  =~ /^([^\/]*)\/([^\/]*)$/) {
								my $range=toRange ($1, $proto, $$rule{'Rule'});
								$range.="/".toRange ($2, $proto, $$rule{'Rule'});
								$other{$range}=1;
							} else {
								die "invalid $proto service: $service:\n$$rule{'Rule'}\n";
							}
						}
						my $again=0;
						my $first=1;
						while ($first || $again) {
							$first=0;
							$again=0;
							LOOP: foreach $service (keys (%other)) {
								next unless exists($other{$service});
								if ($service =~ /^(\d+):(\d+)\/(\d+):(\d+)$/) {
									my $ss=$1;
									my $se=$2;
									my $ds=$3;
									my $de=$4;
									if ($ss>$se || $ds>$de) {
										die "invalid port range: $service:\n$$rule{'Rule'}\n";
									}
									my $test;
									foreach $test (keys (%other)) {
										$test eq $service && next;
										$test =~ /(\d+):(\d+)\/(\d+):(\d+)/;
										if (	$1 == $ss &&
											$2 == $se ) {
											if (	$3 >= $ds &&
												$4 <= $de) {
												delete $other{$test};
												$again=1;
												last LOOP;
											}
											if (	$4 == $ds-1 ||
												($4 >= $ds && $4 <= $de)) {
												$ds=$3;
												$de=$4 if $4>$de;
												delete $other{$service};
												delete $other{$test};
												$other{"$ss:$se/$ds:$de"}=1;
												$again=1;
												last LOOP;
											}
										} elsif (	$3 == $ds &&
												$4 == $de ) {
											if (	$1 >= $ss &&
												$2 <= $se) {
												delete $other{$test};
												$again=1;
												last LOOP;
											}
											if (	$2 == $ss-1 ||
												($2 >= $ss && $2 <= $se)) {
												$ss=$1;
												$se=$2 if $2>$se;
												delete $other{$service};
												delete $other{$test};
												$other{"$ss:$se/$ds:$de"}=1;
												$again=1;
												last LOOP;
											}
										}
									}
								} else {
									 die "invalid service entry: $service:\n$$rule{'Rule'}\n";
								}
							}
						}
						my $entry;
						foreach $entry (keys (%other)) {
							if ($entry =~ /(\d+):(\d+)\/0:65535/) {
								if ($1 != $2) {
									push (@sourcerange, "$1:$2");
								} else {
									push (@multisource, $1);
								}
							} elsif ($entry =~ /0:65535\/(\d+):(\d+)/) {
								if ($1 != $2) {
									push (@destinationrange, "$1:$2");
								} else {
									push (@multidestination, $1);
								}
							} else {
								push (@sourcedestination, $entry);
							}
						}
						if ($serviceprefix eq '') {
							expandRange (\@sourcerange, \@multisource);
							expandRange (\@destinationrange, \@multidestination);
						}
						$$rule{"$serviceprefix\u$proto"}= [\@multisource, \@multidestination, \@sourcerange, \@destinationrange, \@sourcedestination];
						$servicecounter+=@multisource+@multidestination+@sourcerange+@destinationrange+@sourcedestination;
						delete $protocols{"$serviceprefix$proto"};
					}
				}
				if ($serviceprefix ne '' && $servicecounter>1) {
					die "you can specify only one service or service range as nat target:\n$$rule{'Rule'}\n";
				}
				if (exists($$rule{"Service-not"}) && $serviceprefix eq '' && $servicecounter>1) {
					die "you can specify only one service in not statement:\n$$rule{'Rule'}\n";
				}
				if (exists($protocols{"${serviceprefix}icmp"})) {
					if ($serviceprefix ne '') {
						die "can't use icmp nat target:\n$$rule{'Rule'}\n";
					}
					my %icmphash;
					my $message;
					foreach $message (split (/\s+/, $protocols{"${serviceprefix}icmp"})) {
# message validation missing
						$message eq '' && next;
						$icmphash{$message}=1;
					}
					my @array = keys (%icmphash);
					$$rule{"${serviceprefix}ICMP"}=\@array;
					delete $protocols{"${serviceprefix}icmp"};
				}
				if (exists($protocols{"${serviceprefix}ipv6-icmp"})) {
					if ($serviceprefix ne '') {
						die "can't use ipv6-icmp nat target:\n$$rule{'Rule'}\n";
					}
					my %icmp6hash;
					my $message;
					foreach $message (split (/\s+/, $protocols{"${serviceprefix}ipv6-icmp"})) {
# message validation missing
						$message eq '' && next;
						$icmp6hash{$message}=1;
					}
					my @array = keys (%icmp6hash);
					$$rule{"${serviceprefix}ICMP6"}=\@array;
					delete $protocols{"${serviceprefix}ipv6-icmp"};
				}
				if (keys (%protocols)) {
					if ($serviceprefix ne '') {
						die "you can use tcp and udp based nat targets only:\n$$rule{'Rule'}\n";
					}
					my @array = keys (%protocols);
					$$rule{"${serviceprefix}OtherProtocols"} = \@array;
				}
			}
		}
		if (	(exists($$rule{'TranslatedTcp'}) && exists($$rule{'Udp'})) ||
			(exists($$rule{'TranslatedUdp'}) && exists($$rule{'Tcp'}))) {
			die "source protocol and translated protocol must be equal in nat rule:\n$$rule{'Rule'}\n";
		}
		if (exists($$rule{'Flags'})) {
			my $flag;
			foreach $flag (split (/\s+/, $$rule{'Flags'})) {
				$flag eq '' && next;
				if ($flag =~ /^log(\((.+)\)|)$/) {
					$$rule{'Log'}=$2;
				} elsif ($flag =~ /^reject(\((.+)\)|)$/) {
					if ($$rule{'Table'} eq 'nat') {
						die "can't use reject with nat:\n$$rule{'Rule'}\n";
					}
					if ($$rule{'Action'} ne 'DROP') {
						die "rejecting packets in allow rule makes no sense:\n$$rule{'Rule'}\n";
					}
					if ($2) {
						my $param=$2;
						if ($param =~ /^(icmp-(net|host|port|proto)-unreachable|icmp-(net|host)-prohibited|tcp-reset)$/) {
							$$rule{'Reject'}=$param;
						} else {
							die "invalid reject parameter: $param:\n$$rule{'Rule'}\n";
						}
						if ($param eq 'tcp-reset') {
							if (exists($$rule{'OtherProtocols'}) || exists($$rule{'ICMP'}) || exists($$rule{'ICMP6'}) || exists($$rule{'Udp'})) {
								die "can't use tcp-reset with other protocols than tcp:\n$$rule{'Rule'}\n";
							}
							unless (exists($$rule{'Tcp'})) {
								die "need tcp protocol for tcp-reset:\n$$rule{'Rule'}\n";
							}
						}
					} else {
						$$rule{'Reject'}=1;
					}
				} elsif ($flag =~ /^account(\((.+)\)|)$/) {
					if ($$rule{'Table'} eq 'nat') {
						die "can't use accounting with nat:\n$$rule{'Rule'}\n";
					}
					if ($$rule{'Action'} eq 'DROP') {
						die "accounting packets in reject/drop rule makes no sense:\n$$rule{'Rule'}\n";
					}
					if ($2) {
						my $param=$2;
						if ($param =~ /^[a-zA-Z0-9]+$/) {
							$$rule{'Accounting'}=$param;
						} else {
							die "invalid character in accountingname '$param':\n$$rule{'Rule'}\n";
						}
					} else {
						$$rule{'Reject'}='default';
					}
				} elsif ($flag =~ /^limit(\((.*)\)|)$/) {
					if ($$rule{'Action'} eq 'DROP') {
						die "limiting packets in reject/drop rule makes no sense:\n$$rule{'Rule'}\n";
					}
					if (exists($$rule{'Accounting'})) {
						die "limiting packets does not work with accounting in current implementation:\n$$rule{'Rule'}\n";
					}
					if ($2) {
						my $param=$2;
						if ($param =~ /^([^:]+)(:\d+|)$/) {
							if (checkLimit $1) {
								$$rule{'Limit'}=$1;
								if ($2) {
									# no need to check burst since it
									# is guaranteed to be either empty
									# or digits only (plus leading colon).
									# Empty results in other part of if
									# clause.
									my $burst=$2;
									$burst=~s/^://;
									$$rule{'Limit-burst'}=$burst;
								} else {
									$$rule{'Limit-burst'}=$$Sysconfig{'Burst'};
								}
							} else {
								die "invalid limit '$param':\n$$rule{'Rule'}\n";
							}
						} else {
							die "invalid limit descriptionb '$param':\n$$rule{'Rule'}\n";
						}
					} else {
						$$rule{'Limit'}=$$Sysconfig{'Limit'};
						$$rule{'Limit-burst'}=$$Sysconfig{'Burst'};
					}
				} else {
					die "invalid flag: $flag -- $$rule{'Flags'}:\n$$rule{'Rule'}\n";
				}
			}
		}
	}
}

sub genRuleDump_NFT {
	my ($Rules, $Listing, $Sysconfig) = @_;
	my @partial;
	my $rule;
	my %nat;
	my %filter;
	my %mangle;
	my @nat;
	my @filter;
	my @mangle;
	my $table;
	my $chains;
	my $inet;

	if ($ipv6) {
		$inet = "ip6";
	} else {
		$inet = "ip";
	}

	foreach $rule (@$Rules) {

		if ( ($$rule{'Type'} eq "IGNORE-IPV4-ONLY") || ($$rule{'Type'} eq "IGNORE-IPV6-ONLY") ) {
			next;
		}

		my @protocol;
		my @source;
		my @destination;
		my @inputinterface;
		my @outputinterface;
		my @physicalinputinterface;
		my @physicaloutputinterface;
		my @mark;
		my $action;
		my $logaction;
		my $type;
		my $name;
		my $proto;
		my $id;
		my $not;

		if ($$rule{'Table'} eq 'filter') {
			$table=\@filter;
			$chains=\%filter;
		} elsif ($$rule{'Table'} eq 'nat') {
			$table=\@nat;
			$chains=\%nat;
		} elsif ($$rule{'Table'} eq 'mangle') {
			$table=\@mangle;
			$chains=\%mangle;
		} else {
			die "$$rule{'Table'} is not implemented!\n";
		}

		$type="add rule $inet $$rule{'Table'} $$rule{'Type'}";
		if (exists($$rule{'Name'})) {
			$name=$$rule{'Name'};
			$name=~s/\s+//g;
		} else {
			$name="-";
		}
		$id=$$rule{'Id'};

		if (exists($$rule{'Reject'})) {
			if ($$rule{'Reject'} ne '1') {
				$action="counter reject with $$rule{'Reject'}";
				$action =~ s/-/ /g;
			} else {
				$action="counter jump MYREJECT";
			}
			$logaction="REJECT";
		} elsif ($$rule{'Action'} eq "TCPMSS") {
			$action="-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu";
			$logaction="TCPMSS";
		} elsif ($$rule{'Action'} eq "MARK") {
			$action="-j MARK --set-mark $$rule{'Mark'}";
			$logaction="MARK";
		} else {
			if ( $$rule{'Action'} =~ /^(ACCEPT|DROP|RETURN|MASQUERADE)$/) {
				$action="counter ".lc $$rule{'Action'};
			} else {
				$action="counter jump $$rule{'Action'}";
			}
			$logaction=$$rule{'Action'};
		}

		if (exists($$rule{"Service-not"})) {
			$not='!';
		} else {
			$not='';
		}

		foreach $proto (qw(tcp udp)) {
			if (exists($$rule{"\u$proto"})) {
				my $string;
				my $entry;
				foreach $entry (qw(0 1)) {
					my $multiport;
					my $count=0;
					foreach $multiport (@{$$rule{"\u$proto"}[$entry]}) {
						if ($count==0) {
							$string='';
						}
						$string.="$multiport,";
						$count++;
						if ($count==15) {
							$string =~ s/,$//;
							$string="$proto multiport ".($entry==1?"d":"s")."port ".$string;
							push (@protocol, $string);
							$string='';
							$count=0;
						}
					}
					if (defined($string) && $count) {
						$string =~ s/,$//;
						if ($count > 1) {
							$string="$proto multiport ".($entry==1?"d":"s")."port ".$string;
						} else {
							$string="$proto ".($entry==1?"d":"s")."port ".$string;
						}
						push (@protocol, $string);
					}
				}
				my $range;
				foreach $range (@{$$rule{"\u$proto"}[2]}) {
					$range =~ s/\:/-/g;
					push (@protocol, "$not $proto sport $range");
				}
				foreach $range (@{$$rule{"\u$proto"}[3]}) {
					$range =~ s/\:/-/g;
					push (@protocol, "$not $proto dport $range");
				}
				foreach $range (@{$$rule{"\u$proto"}[4]}) {
					$range =~ s/\:/-/g;
					$range =~ /^(.+)\/(.+)$/;
					push (@protocol, "$not $proto sport $1 $not $proto dport $2");
				}
			}
		}
		if (exists($$rule{'ICMP'}) && (! $ipv6)) {
			my $type;
			foreach $type (@{$$rule{'ICMP'}}) {
				if ($type eq 'all') {
					push (@protocol, "$not icmp");
				} else {
					push (@protocol, "icmp $not type $type");
				}
			}
		}
		if (exists($$rule{'ICMP6'}) and ($ipv6)) {
			my $type;
			foreach $type (@{$$rule{'ICMP6'}}) {
				if ($type eq 'all') {
					push (@protocol, "$not icmpv6");
				} else {
					push (@protocol, "icmpv6 $not $type");
				}
			}
		}
		if (exists($$rule{'OtherProtocols'})) {
			my $proto;
			foreach $proto (@{$$rule{'OtherProtocols'}}) {
				push (@protocol, "$not $proto");
			}
		}
		if (exists($$rule{'Source'})) {
			if (exists($$rule{'Source-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $source;
			foreach $source (@{$$rule{'Source'}}) {
				if ($source =~ /(.+)=(.+)/ && ($$rule{'Table'} eq 'filter')) {
					push (@source, "$not ip saddr $1 mac $not --mac-source $2");
				} else {
					$source =~ /([^=]+)/;
					push (@source, "$not ip saddr $1");
				}
			}
		}
		if (exists($$rule{'Destination'})) {
			if (exists($$rule{'Destination-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $destination;
			foreach $destination (@{$$rule{'Destination'}}) {
				$destination =~ /([^=]+)/;
				push (@destination, "$not $inet daddr $1");
			}
		}
		if (exists($$rule{'TranslatedSource'})) {
			my $source;
			$source=${$$rule{'TranslatedSource'}}[0];
			$source =~ /([^=]+)/;
			$source=$1;
			my $ip = NetAddr::IP->new($source) || die "not a valid network: $source\n";
			my $net=$ip->network();
			my $bcast = $ip->broadcast();
			if ($net ne $bcast) {
				$source="$net-$bcast";
			}
			$source =~ s/\/[^-]+//g;
#			$action="-t nat ".$action;
			$action.=" --to-source $source";
		}
		if (exists($$rule{'TranslatedDestination'})) {
			my $destination;
			$destination=${$$rule{'TranslatedDestination'}}[0];
			$destination =~ /([^=]+)/;
			$destination=$1;
			my $ip = NetAddr::IP->new($destination) || die "not a valid network: $destination\n";
			my $net=$ip->network();
			my $bcast = $ip->broadcast();
			if ($net ne $bcast) {
				$destination="$net-$bcast";
			}
			$destination =~ s/\/[^-]+//g;
#			$action="-t nat ".$action;
			$action.=" --to-destination $destination";
		}

		foreach $proto (qw(tcp udp)) {
			if (exists($$rule{"Translated\u$proto"})) {
				my $ref = $$rule{"Translated\u$proto"};
				if (defined($$ref[1][0])) {
					$action.=":$$ref[1][0]";
					$action="$proto ".$action;
				}
				if (defined($$ref[3][0])) {
					$action.=":$$ref[3][0]";
					$action="$proto ".$action;
				}
				last;
			}
		}

		if (exists($$rule{'InputInterface'})) {
			if (exists($$rule{'InputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $input;
			foreach $input (@{$$rule{'InputInterface'}}) {
				push (@inputinterface, "$not iifname \"$input\"");
			}
		}
		if (exists($$rule{'OutputInterface'})) {
			if (exists($$rule{'OutputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $output;
			foreach $output (@{$$rule{'OutputInterface'}}) {
				push (@outputinterface, "$not oifname \"$output\"");
			}
		}
		if (exists($$rule{'PhysicalInputInterface'})) {
			if (exists($$rule{'PhysicalInputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $input;
			foreach $input (@{$$rule{'PhysicalInputInterface'}}) {
				push (@physicalinputinterface, "-m physdev $not --physdev-in $input");
			}
		}
		if (exists($$rule{'PhysicalOutputInterface'})) {
			if (exists($$rule{'PhysicalOutputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $output;
			foreach $output (@{$$rule{'PhysicalOutputInterface'}}) {
				push (@physicaloutputinterface, "-m physdev $not --physdev-out $output");
			}
		}
		if (exists($$rule{'MarkMatch'})) {
			my $mark;
			foreach $mark (@{$$rule{'MarkMatch'}}) {
				push (@mark, "-m mark --mark $mark");
			}
		}

		if (exists($$rule{'Log'})) {
			my $chain = "${id}$$rule{'Action'}log";
			$$chains{$chain}=1;
			my $logid;
			if ($$rule{'Log'}) {
				$logid=$$rule{'Log'};
			} else {
				$logid=$name;
			}
			push (@$table, "add rule $inet $$rule{'Table'} CHAIN_$chain limit rate $$Sysconfig{'LogLimit'} burst $$Sysconfig{'LogBurst'} packets counter log prefix \"$$Sysconfig{'LogPrefix'} $logaction ($logid): \" level $$Sysconfig{'LogLevel'} flags tcp options flags ip options");
			push (@$table, "add rule $inet $$rule{'Table'} CHAIN_$chain $action");
			$action="counter jump CHAIN_$chain";
		}
		if (exists($$rule{'Accounting'})) {
			my $accountchain="$$Sysconfig{'AccountPrefix'}$$rule{'Accounting'}";
			unless (exists($$chains{"$accountchain"})) {
				$$chains{"$accountchain"}=1;
				push (@$table, "add rule $inet $$rule{'Table'} CHAIN_$accountchain $action");
			}
			my $accountrules="${id}_ACCOUNTING_$$rule{'Accounting'}";
			$$chains{$accountrules}=1;
			push (@$table, "$type counter jump $accountrules");
			push (@$table, "add rule $inet $$rule{'Table'} ACCOUNTING$$rule{'Type'} counter jump CHAIN_$accountrules");
			$type="add rule $inet $$rule{'Table'} $accountrules ";
			$action=" counter jump CHAIN_$accountchain";
		}
		if (exists($$rule{'Limit'})) {
			$action=" limit rate $$rule{'Limit'} burst $$rule{'Limit-burst'} packets $action";
		}
		my @rulearray = (\@inputinterface, \@outputinterface, \@physicalinputinterface, \@physicaloutputinterface, \@protocol, \@source, \@destination, \@mark);

		my $level=1;
		my $again=1;
		while ($again) {
			@partial = ();
			$again=0;
			my $array;
			# adjust if you have many entries...
			my $depth=0xFFFF;
			foreach $array (@rulearray) {
				if (@$array && $depth>@$array) {
					$depth=@$array;
				}
			}
			foreach $array (@rulearray) {
				if (@$array==$depth) {
					my $i;
					for ($i=0; $i<@$array; $i++) {
						$partial[$i].=" $$array[$i]";
					}
					@$array = ();
					if ($depth != 1) {
						last;
					}
				}
			}
			foreach $array (@rulearray) {
				if (@$array) {
					$again=1;
					last;
				}
			}
			my $jumpto;
			if ($again) {
				$jumpto="counter jump CHAIN_${id}_$level";
			} else {
				$jumpto=$action;
			}
			if (@partial) {
				my $newjumpto;
				my $part;
				foreach $part (@partial) {
					$newjumpto=$jumpto;
					if ($part =~ /-p (udp|tcp)/ && $jumpto =~ /-p (udp|tcp)/) {
						$newjumpto =~ s/-p (udp|tcp) -m (udp|tcp)//;
					}
					push (@$table, $type." $part $newjumpto");
				}
			} else {
				push (@$table, "$type $jumpto");
			}
			if ($again) {
				$type="add rule $inet $$rule{'Table'} CHAIN_${id}_$level";
				$$chains{"${id}_$level"}=1;
				$level++;
			}
		}
	}

	# make sure, all rules get dropped before populating tables anew
	push (@$Listing, "flush ruleset $inet");

	my $entry;
	foreach $entry (qw(mangle filter nat)) {
		if ($entry eq "nat" && $ipv6 == 1) {next};
		my $chain;
		push (@$Listing, "add table $inet $entry");
		if ($entry eq 'filter') {
			$table=\@filter;
			$chains=\%filter;
			push (@$Listing, "add chain $inet filter MYREJECT");
			push (@$Listing, "add chain $inet filter STATENOTNEW");
			foreach (qw(INPUT OUTPUT FORWARD)) {
				push (@$Listing, "add chain $inet filter ACCOUNTING$_");
				push (@$Listing, "add chain $inet filter ACCOUNTINGSTATELESS$_");
				push (@$Listing, "add chain $inet filter STATE$_");
				push (@$Listing, "add chain $inet filter STATELESS$_");
				push (@$Listing, "add chain $inet filter $_ { type filter hook ".lc $_." priority 0; policy drop; }");
				push (@$Listing, "add rule $inet filter $_ counter jump STATE$_");
				push (@$Listing, "add rule $inet filter STATE$_ ct state invalid counter jump STATELESS$_");
				push (@$Listing, "add rule $inet filter STATE$_ counter jump ACCOUNTING$_");
				push (@$Listing, "add rule $inet filter STATE$_ ct state related,established counter accept");
				if ($ipv6) {
					push (@$Listing, "add rule ip6 filter STATE$_ ! -p ipv6-icmp -m state ! --state NEW -j STATENOTNEW");
				} else {
					push (@$Listing, "add rule ip filter STATE$_ ct state != new counter jump STATENOTNEW");
				}
				push (@$Listing, "add rule $inet filter STATELESS$_ counter jump ACCOUNTINGSTATELESS$_");
			}
			push (@$Listing, "add rule $inet filter STATENOTNEW limit rate $$Sysconfig{'LogLimit'} burst $$Sysconfig{'LogBurst'} packets counter log prefix \"$$Sysconfig{'LogPrefix'} STATE NOT NEW: \" level $$Sysconfig{'LogLevel'} flags tcp options flags ip options");
			push (@$Listing, "add rule $inet filter STATENOTNEW counter drop");
			push (@$Listing, "add rule $inet filter MYREJECT counter reject with tcp reset");
			if ($ipv6) {
				push (@$Listing, "add rule $inet filter MYREJECT counter reject --reject-with icmp6-port-unreachable");
			} else {
				push (@$Listing, "add rule $inet filter MYREJECT counter reject");
			}
		} elsif ($entry eq 'nat') {
			$table=\@nat;
			$chains=\%nat;
			push (@$Listing, "add chain $inet nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }");
			foreach (qw(PREROUTING OUTPUT)) {
				push (@$Listing, "add chain $inet nat $_ { type nat hook ".lc $_." priority -100; policy accept; }");
			}
		} else {
			$table=\@mangle;
			$chains=\%mangle;
			push (@$Listing, "add chain $inet mangle PREROUTING { type filter hook prerouting priority -150; policy accept; }");
			push (@$Listing, "add chain $inet mangle OUTPUT { type route hook output priority -150; policy accept; }");
		}
		foreach (keys(%$chains)) {
			push (@$Listing, "add chain $inet filter CHAIN_$_");
		}
		push (@$Listing, "#");
		push (@$Listing, "# beginning of user generated $entry rules");
		push (@$Listing, "#");
		foreach (@$table) {
			push (@$Listing, $_);
		}
		push (@$Listing, "#");
		push (@$Listing, "# end of user generated $entry rules");
		push (@$Listing, "#");
		if ($entry eq 'filter') {
			foreach (qw(INPUT OUTPUT FORWARD)) {
				push (@$Listing, "add rule $inet filter STATELESS$_ limit rate $$Sysconfig{'LogLimit'} burst $$Sysconfig{'LogBurst'} packets counter log prefix \"$$Sysconfig{'LogPrefix'} INVALID STATE: \"  level $$Sysconfig{'LogLevel'} flags tcp options flags ip options");
				push (@$Listing, "add rule $inet filter STATELESS$_ counter drop");
			}
		}
	}
}

sub genRuleDump_IPTABLES {
	my ($Rules, $Listing, $Sysconfig) = @_;
	my @partial;
	my $rule;
	my %nat;
	my %filter;
	my %mangle;
	my @nat;
	my @filter;
	my @mangle;
	my $table;
	my $chains;

	foreach $rule (@$Rules) {

		if ( ($$rule{'Type'} eq "IGNORE-IPV4-ONLY") || ($$rule{'Type'} eq "IGNORE-IPV6-ONLY") ) {
			next;
		}

		my @protocol;
		my @source;
		my @destination;
		my @inputinterface;
		my @outputinterface;
		my @physicalinputinterface;
		my @physicaloutputinterface;
		my @mark;
		my $action;
		my $logaction;
		my $type;
		my $name;
		my $proto;
		my $id;
		my $not;

		if ($$rule{'Table'} eq 'filter') {
			$table=\@filter;
			$chains=\%filter;
		} elsif ($$rule{'Table'} eq 'nat') {
			$table=\@nat;
			$chains=\%nat;
		} elsif ($$rule{'Table'} eq 'mangle') {
			$table=\@mangle;
			$chains=\%mangle;
		} else {
			die "$$rule{'Table'} is not implemented!\n";
		}

		$type="-A $$rule{'Type'}";
		if (exists($$rule{'Name'})) {
			$name=$$rule{'Name'};
			$name=~s/\s+//g;
		} else {
			$name="-";
		}
		$id=$$rule{'Id'};

		if (exists($$rule{'Reject'})) {
			if ($$rule{'Reject'} ne '1') {
				if ($$rule{'Reject'} =~ /tcp/) {
					$action="-p tcp -m tcp -j REJECT --reject-with $$rule{'Reject'}";
				} else {
					$action="-j REJECT --reject-with $$rule{'Reject'}";
				}
			} else {
				$action="-j MYREJECT";

			}
			$logaction="REJECT";
		} elsif ($$rule{'Action'} eq "TCPMSS") {
			$action="-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu";
			$logaction="TCPMSS";
		} elsif ($$rule{'Action'} eq "MARK") {
			$action="-j MARK --set-mark $$rule{'Mark'}";
			$logaction="MARK";
		} else {
			$action="-j $$rule{'Action'}";
			$logaction=$$rule{'Action'};
		}

		if (exists($$rule{"Service-not"})) {
			$not='!';
		} else {
			$not='';
		}

		foreach $proto (qw(tcp udp)) {
			if (exists($$rule{"\u$proto"})) {
				my $string;
				my $entry;
				foreach $entry (qw(0 1)) {
					my $multiport;
					my $count=0;
					foreach $multiport (@{$$rule{"\u$proto"}[$entry]}) {
						if ($count==0) {
							$string='';
						}
						$string.="$multiport,";
						$count++;
						if ($count==15) {
							$string =~ s/,$//;
							$string="-p $proto -m multiport --".($entry==1?"d":"s")."port ".$string;
							push (@protocol, $string);
							$string='';
							$count=0;
						}
					}
					if (defined($string) && $count) {
						$string =~ s/,$//;
						if ($count > 1) {
							$string="-p $proto -m multiport --".($entry==1?"d":"s")."port ".$string;
						} else {
							$string="-p $proto -m $proto --".($entry==1?"d":"s")."port ".$string;
						}
						push (@protocol, $string);
					}
				}
				my $range;
				foreach $range (@{$$rule{"\u$proto"}[2]}) {
					push (@protocol, "-p $proto -m $proto $not --sport $range");
				}
				foreach $range (@{$$rule{"\u$proto"}[3]}) {
					push (@protocol, "-p $proto -m $proto $not --dport $range");
				}
				foreach $range (@{$$rule{"\u$proto"}[4]}) {
					$range =~ /^(.+)\/(.+)$/;
					push (@protocol, "-p $proto -m $proto $not --sport $1 $not --dport $2");
				}
			}
		}
		if (exists($$rule{'ICMP'}) && (! $ipv6)) {
			my $type;
			foreach $type (@{$$rule{'ICMP'}}) {
				if ($type eq 'all') {
					push (@protocol, "$not -p icmp");
				} else {
					push (@protocol, "-p icmp -m icmp $not --icmp-type $type");
				}
			}
		}
		if (exists($$rule{'ICMP6'}) and ($ipv6)) {
			my $type;
			foreach $type (@{$$rule{'ICMP6'}}) {
				if ($type eq 'all') {
					push (@protocol, "$not -p icmpv6");
				} else {
					push (@protocol, "-p icmpv6 -m icmpv6 $not --icmpv6-type $type");
				}
			}
		}
		if (exists($$rule{'OtherProtocols'})) {
			my $proto;
			foreach $proto (@{$$rule{'OtherProtocols'}}) {
				push (@protocol, "$not -p $proto");
			}
		}
		if (exists($$rule{'Source'})) {
			if (exists($$rule{'Source-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $source;
			foreach $source (@{$$rule{'Source'}}) {
				if ($source =~ /(.+)=(.+)/ && ($$rule{'Table'} eq 'filter')) {
					push (@source, "$not -s $1 -m mac $not --mac-source $2");
				} else {
					$source =~ /([^=]+)/;
					push (@source, "$not -s $1");
				}
			}
		}
		if (exists($$rule{'Destination'})) {
			if (exists($$rule{'Destination-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $destination;
			foreach $destination (@{$$rule{'Destination'}}) {
				$destination =~ /([^=]+)/;
				push (@destination, "$not -d $1");
			}
		}
		if (exists($$rule{'TranslatedSource'})) {
			my $source;
			$source=${$$rule{'TranslatedSource'}}[0];
			$source =~ /([^=]+)/;
			$source=$1;
			my $ip = NetAddr::IP->new($source) || die "not a valid network: $source\n";
			my $net=$ip->network();
			my $bcast = $ip->broadcast();
			if ($net ne $bcast) {
				$source="$net-$bcast";
			}
			$source =~ s/\/[^-]+//g;
#			$action="-t nat ".$action;
			$action.=" --to-source $source";
		}
		if (exists($$rule{'TranslatedDestination'})) {
			my $destination;
			$destination=${$$rule{'TranslatedDestination'}}[0];
			$destination =~ /([^=]+)/;
			$destination=$1;
			my $ip = NetAddr::IP->new($destination) || die "not a valid network: $destination\n";
			my $net=$ip->network();
			my $bcast = $ip->broadcast();
			if ($net ne $bcast) {
				$destination="$net-$bcast";
			}
			$destination =~ s/\/[^-]+//g;
#			$action="-t nat ".$action;
			$action.=" --to-destination $destination";
		}

		foreach $proto (qw(tcp udp)) {
			if (exists($$rule{"Translated\u$proto"})) {
				my $ref = $$rule{"Translated\u$proto"};
				if (defined($$ref[1][0])) {
					$action.=":$$ref[1][0]";
					$action="-p $proto -m $proto ".$action;
				}
				if (defined($$ref[3][0])) {
					$action.=":$$ref[3][0]";
					$action="-p $proto -m $proto ".$action;
				}
				last;
			}
		}

		if (exists($$rule{'InputInterface'})) {
			if (exists($$rule{'InputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $input;
			foreach $input (@{$$rule{'InputInterface'}}) {
				push (@inputinterface, "$not -i $input");
			}
		}
		if (exists($$rule{'OutputInterface'})) {
			if (exists($$rule{'OutputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $output;
			foreach $output (@{$$rule{'OutputInterface'}}) {
				push (@outputinterface, "$not -o $output");
			}
		}
		if (exists($$rule{'PhysicalInputInterface'})) {
			if (exists($$rule{'PhysicalInputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $input;
			foreach $input (@{$$rule{'PhysicalInputInterface'}}) {
				push (@physicalinputinterface, "-m physdev $not --physdev-in $input");
			}
		}
		if (exists($$rule{'PhysicalOutputInterface'})) {
			if (exists($$rule{'PhysicalOutputInterface-not'})) {
				$not='!';
			} else {
				$not='';
			}
			my $output;
			foreach $output (@{$$rule{'PhysicalOutputInterface'}}) {
				push (@physicaloutputinterface, "-m physdev $not --physdev-out $output");
			}
		}
		if (exists($$rule{'MarkMatch'})) {
			my $mark;
			foreach $mark (@{$$rule{'MarkMatch'}}) {
				push (@mark, "-m mark --mark $mark");
			}
		}

		if (exists($$rule{'Log'})) {
			my $chain = "${id}$$rule{'Action'}log";
			$$chains{$chain}=1;
			my $logid;
			if ($$rule{'Log'}) {
				$logid=$$rule{'Log'};
			} else {
				$logid=$name;
			}
			push (@$table, "-A CHAIN_$chain -m limit --limit $$Sysconfig{'LogLimit'} --limit-burst $$Sysconfig{'LogBurst'} -j LOG --log-prefix \"$$Sysconfig{'LogPrefix'} $logaction ($logid): \" --log-level $$Sysconfig{'LogLevel'} --log-tcp-options --log-ip-options");
			push (@$table, "-A CHAIN_$chain $action");
			$action="-j CHAIN_$chain";
		}
		if (exists($$rule{'Accounting'})) {
			my $accountchain="$$Sysconfig{'AccountPrefix'}$$rule{'Accounting'}";
			unless (exists($$chains{"$accountchain"})) {
				$$chains{"$accountchain"}=1;
				push (@$table, "-A CHAIN_$accountchain $action");
			}
			my $accountrules="${id}_ACCOUNTING_$$rule{'Accounting'}";
			$$chains{$accountrules}=1;
			push (@$table, "$type -j $accountrules");
			push (@$table, "-A ACCOUNTING$$rule{'Type'} -j CHAIN_$accountrules");
			$type="-A $accountrules ";
			$action=" -j CHAIN_$accountchain";
		}
		if (exists($$rule{'Limit'})) {
			$action=" -m limit --limit $$rule{'Limit'} --limit-burst $$rule{'Limit-burst'} $action";
		}
		my @rulearray = (\@inputinterface, \@outputinterface, \@physicalinputinterface, \@physicaloutputinterface, \@protocol, \@source, \@destination, \@mark);

		my $level=1;
		my $again=1;
		while ($again) {
			@partial = ();
			$again=0;
			my $array;
			# adjust if you have many entries...
			my $depth=0xFFFF;
			foreach $array (@rulearray) {
				if (@$array && $depth>@$array) {
					$depth=@$array;
				}
			}
			foreach $array (@rulearray) {
				if (@$array==$depth) {
					my $i;
					for ($i=0; $i<@$array; $i++) {
						$partial[$i].=" $$array[$i]";
					}
					@$array = ();
					if ($depth != 1) {
						last;
					}
				}
			}
			foreach $array (@rulearray) {
				if (@$array) {
					$again=1;
					last;
				}
			}
			my $jumpto;
			if ($again) {
				$jumpto="-j CHAIN_${id}_$level";
			} else {
				$jumpto=$action;
			}
			if (@partial) {
				my $newjumpto;
				my $part;
				foreach $part (@partial) {
					$newjumpto=$jumpto;
					if ($part =~ /-p (udp|tcp)/ && $jumpto =~ /-p (udp|tcp)/) {
						$newjumpto =~ s/-p (udp|tcp) -m (udp|tcp)//;
					}
					push (@$table, $type." $part $newjumpto");
				}
			} else {
				push (@$table, "$type $jumpto");
			}
			if ($again) {
				$type="-A CHAIN_${id}_$level";
				$$chains{"${id}_$level"}=1;
				$level++;
			}
		}
	}

	my $entry;
	foreach $entry (qw(mangle filter nat)) {
		if ($entry eq "nat" && $ipv6 == 1) {next};
		my $chain;
		push (@$Listing, "*$entry");
		if ($entry eq 'filter') {
			$table=\@filter;
			$chains=\%filter;
			push (@$Listing, ":MYREJECT - [0:0]");
			push (@$Listing, ":STATENOTNEW - [0:0]");
			foreach (qw(INPUT OUTPUT FORWARD)) {
				push (@$Listing, ":ACCOUNTING$_ - [0:0]");
				push (@$Listing, ":ACCOUNTINGSTATELESS$_ - [0:0]");
				push (@$Listing, ":STATE$_ - [0:0]");
				push (@$Listing, ":STATELESS$_ - [0:0]");
				push (@$Listing, ":$_ DROP [0:0]");
				push (@$Listing, "-A $_ -j STATE$_");
				push (@$Listing, "-A STATE$_ -m state --state INVALID -j STATELESS$_");
				push (@$Listing, "-A STATE$_ -j ACCOUNTING$_");
				push (@$Listing, "-A STATE$_ -m state --state ESTABLISHED,RELATED -j ACCEPT");
				if ($ipv6) {
					push (@$Listing, "-A STATE$_ ! -p ipv6-icmp -m state ! --state NEW -j STATENOTNEW");
				} else {
					push (@$Listing, "-A STATE$_ -m state ! --state NEW -j STATENOTNEW");
				}
				push (@$Listing, "-A STATELESS$_ -j ACCOUNTINGSTATELESS$_");
			}
			push (@$Listing, "-A STATENOTNEW -m limit --limit $$Sysconfig{'LogLimit'} --limit-burst $$Sysconfig{'LogBurst'} -j LOG --log-prefix \"$$Sysconfig{'LogPrefix'} STATE NOT NEW: \"  --log-level $$Sysconfig{'LogLevel'} --log-tcp-options --log-ip-options");
			push (@$Listing, "-A STATENOTNEW -j DROP");
			push (@$Listing, "-A MYREJECT -m tcp -p tcp -j REJECT --reject-with tcp-reset");
			if ($ipv6) {
				push (@$Listing, "-A MYREJECT -j REJECT --reject-with icmp6-port-unreachable");
			} else {
				push (@$Listing, "-A MYREJECT -j REJECT --reject-with icmp-port-unreachable");
			}
		} elsif ($entry eq 'nat') {
			$table=\@nat;
			$chains=\%nat;
			foreach (qw(POSTROUTING PREROUTING OUTPUT)) {
				push (@$Listing, ":$_ ACCEPT [0:0]");
			}
		} else {
			$table=\@mangle;
			$chains=\%mangle;
			foreach (qw(PREROUTING OUTPUT)) {
				push (@$Listing, ":$_ ACCEPT [0:0]");
			}
		}
		foreach (keys(%$chains)) {
			push (@$Listing, ":CHAIN_$_ - [0:0]");
		}
		push (@$Listing, "#");
		push (@$Listing, "# beginning of user generated $entry rules");
		push (@$Listing, "#");
		foreach (@$table) {
			push (@$Listing, $_);
		}
		push (@$Listing, "#");
		push (@$Listing, "# end of user generated $entry rules");
		push (@$Listing, "#");
		if ($entry eq 'filter') {
			foreach (qw(INPUT OUTPUT FORWARD)) {
				push (@$Listing, "-A STATELESS$_ -m limit --limit $$Sysconfig{'LogLimit'} --limit-burst $$Sysconfig{'LogBurst'} -j LOG --log-prefix \"$$Sysconfig{'LogPrefix'} INVALID STATE: \"  --log-level $$Sysconfig{'LogLevel'} --log-tcp-options --log-ip-options");
				push (@$Listing, "-A STATELESS$_ -j DROP");
			}
		}
		push (@$Listing, "COMMIT");
	}
}

sub printRules {
	my ($Listing) = @_;
	@$Listing=map { $_."\n" } @$Listing;
	print @$Listing;
}

sub signalCatcher {
	$SignalCatched=1;
}

sub applyRules_NFT {
	my ($timeout, $Listing, $Sysconfig) = @_;
	my @oldrules;
	my $error;

	@$Listing=map { $_."\n" } @$Listing;
	open (NFT, '/usr/sbin/nft list ruleset|');
	@oldrules = <NFT>;
	close (NFT);

	$SIG{'INT'} = 'signalCatcher';
	$SIG{'KILL'} = 'signalCatcher';
	$SIG{'QUIT'} = 'signalCatcher';
	$SIG{'TERM'} = 'signalCatcher';

	open (NFT_DISK, '>/tmp/nftrules');
	print NFT_DISK @$Listing;
	close (NFT_DISK);

	open (NFT, '|/usr/sbin/nft -f -');
	print NFT @$Listing;
	close (NFT);
	$error=$?;

	if ($timeout && !$error) {
		sleep $timeout;
	}
	if ($timeout || $SignalCatched || $error) {
		open (NFT, '|/usr/sbin/nft -f -');
		print NFT @oldrules;
		close (NFT);
		if ($SignalCatched) {
			die "aborted. old rules restored.\n";
		} elsif ($error) {
			die "error in generated rules\n";
		}
	}
}

sub applyRules_IPTABLES {
	my ($timeout, $Listing, $Sysconfig) = @_;
	my @oldrules;
	my $error;
	my $save_cmd;
	my $restore_cmd;

	if (%$Sysconfig{'filtercommand'} eq 'iptables') {
		if ($ipv6) {
			$save_cmd    = "/usr/sbin/ip6tables-save";
			$restore_cmd = "/usr/sbin/ip6tables-restore";
		} else {
			$save_cmd    = "/usr/sbin/iptables-save";
			$restore_cmd = "/usr/sbin/iptables-restore";
		}
	} elsif (%$Sysconfig{'filtercommand'} eq 'iptables-nft') {
		if ($ipv6) {
			$save_cmd    = "/usr/sbin/ip6tables-nft-save";
			$restore_cmd = "/usr/sbin/ip6tables-nft-restore";
		} else {
			$save_cmd    = "/usr/sbin/iptables-nft-save";
			$restore_cmd = "/usr/sbin/iptables-nft-restore";
		}
	} elsif (%$Sysconfig{'filtercommand'} eq 'iptables-legacy') {
		if ($ipv6) {
			$save_cmd    = "/usr/sbin/ip6tables-legacy-save";
			$restore_cmd = "/usr/sbin/ip6tables-legacy-restore";
		} else {
			$save_cmd    = "/usr/sbin/iptables-legacy-save";
			$restore_cmd = "/usr/sbin/iptables-legacy-restore";
		}
	}

	@$Listing=map { $_."\n" } @$Listing;
	open (IPT, "$save_cmd|");
	@oldrules = <IPT>;
	close (IPT);

	$SIG{'INT'} = 'signalCatcher';
	$SIG{'KILL'} = 'signalCatcher';
	$SIG{'QUIT'} = 'signalCatcher';
	$SIG{'TERM'} = 'signalCatcher';

	open (IPT, "|$restore_cmd");
	print IPT @$Listing;
	close (IPT);
	$error=$?;

	if ($timeout && !$error) {
		sleep $timeout;
	}
	if ($timeout || $SignalCatched || $error) {
		open (IPT, "|$restore_cmd");
		print IPT @oldrules;
		close (IPT);
		if ($SignalCatched) {
			die "aborted. old rules restored.\n";
		} elsif ($error) {
			die "error in generated rules\n";
		}
	}
}

sub readCommandLine {
	my %Networks;
	my %Services;
	my %Protocols;
	my %Interfaces;
	my %Sysconfig;
	my %Marker;
	my @Rules;
	my @Listing;
	my $test=0;
	my $print=0;
	my $disable=0;
	my $writeconfigfile;
	my $writeldapruleset;
	my $ldap;
	my $readldap=0;
	my $writeldap=0;
	my $mesg;
	my $ldapbase='o=unconfigured';
	my $ldapserver='localhost:389';
	my $ldapruleset='std';
	my $ldapbinddn;
	my $ldappassword;
	my $timeout=0;

	if (exists($ENV{'FILTER_COMMAND'})) {
		$Sysconfig{'FilterCommand'}=$ENV{'FILTER_COMMAND'};
	} else {
		$Sysconfig{'FilterCommand'}='nft';
	}
	if (exists($ENV{'LOGLIMIT'})) {
		$Sysconfig{'LogLimit'}=$ENV{'LOGLIMIT'};
	} else {
		$Sysconfig{'LogLimit'}='20/minute';
	}
	if (exists($ENV{'LOGBURST'})) {
		$Sysconfig{'LogBurst'}=$ENV{'LOGBURST'};
	} else {
		$Sysconfig{'LogBurst'}='5';
	}
	if (exists($ENV{'LOGLEVEL'})) {
		$Sysconfig{'LogLevel'}=$ENV{'LOGLEVEL'};
	} else {
		$Sysconfig{'LogLevel'}='debug';
	}
	if (exists($ENV{'LOGPREFIX'})) {
		$Sysconfig{'LogPrefix'}=$ENV{'LOGPREFIX'};
	} else {
		$Sysconfig{'LogPrefix'}='FW';
	}
	if (exists($ENV{'LIMIT'})) {
		$Sysconfig{'Limit'}=$ENV{'LIMIT'};
	} else {
		$Sysconfig{'Limit'}='20/minute';
	}
	if (exists($ENV{'BURST'})) {
		$Sysconfig{'Burst'}=$ENV{'BURST'};
	} else {
		$Sysconfig{'Burst'}='5';
	}
	if (exists($ENV{'ACCOUNTPREFIX'})) {
		$Sysconfig{'AccountPrefix'}=$ENV{'ACCOUNTPREFIX'};
	} else {
		$Sysconfig{'AccountPrefix'}='ACC_';
	}
	my %opt;
	getopts('6c:tpds:b:r:T:C:R:D:w:W', \%opt) || uifUsg ();

	$ipv6 = 1 if $opt{'6'};
	$configfile=$configfile6 if $opt{'6'};
	$configfile = $opt{'c'} if $opt{'c'};
	$test = 1 if $opt{'t'};
	$print = 1 if $opt{'p'};
	$disable = 1 if $opt{'d'};
	if ($opt{'T'}) {
		if ($opt{'T'} =~ /^(\d+)$/) {
			$timeout=$1;
		} else {
			die "timeout must be numeric: $opt{'T'}\n";
			uifUsg ();
		}
	}
	if ($opt{'s'}) {
		$ldapserver=$opt{'s'};
	}
	if ($opt{'b'}) {
		$ldapbase=$opt{'b'};
	}
	if ($opt{'r'}) {
		$readldap=1;
		$ldapruleset=$opt{'r'};
	}
	if ($opt{'C'}) {
		$ldap=1;
		$writeconfigfile=$opt{'C'};
	}
	if ($opt{'R'}) {
		$writeldap=1;
		$writeldapruleset=$opt{'R'};
	}
	if ($opt{'D'}) {
		$ldapbinddn=$opt{'D'};
	}
	if ($opt{'w'}) {
		$ldappassword=$opt{'w'};
	}
	if ($opt{'W'}) {
		print "password: ";
		$ldappassword=<STDIN>;
		chomp($ldappassword);
	}

	if ($ipv6) {
		if (exists($ENV{'LOGPREFIX6'})) {
			$Sysconfig{'LogPrefix'}=$ENV{'LOGPREFIX6'};
		} else {
			$Sysconfig{'LogPrefix'}='FW6';
		}
	}

	if ($readldap || $writeldap) {
		if ($LDAPENABLED == 0) { die "To use LDAP features be sure to install Net::LDAP from the Debian package libnet-ldap-perl" } ;
		$ldap = Net::LDAP->new($ldapserver) or die "$@";
		if ($ldapbinddn && ($ldappassword eq "")) {
			$mesg=$ldap->bind(	$ldapbinddn);
		} elsif ($ldapbinddn && $ldappassword) {
			$mesg=$ldap->bind(	$ldapbinddn,
						password => $ldappassword);
		} else {
			$mesg=$ldap->bind;
		}
		if ($mesg->is_error) {
			die "can't bind to ldap server: ".$mesg->error."\n";
			uifUsg ();
		}
	}

	unless ($disable) {
		if ($readldap) {
			readLdap ($ldap, $ldapbase, $ldapruleset, \%Networks, \%Services, \%Interfaces, \%Protocols, \@Rules, \%Sysconfig, \%Marker);
		} else {
			my $Id=0;
			readConfig ($configfile, \%Networks, \%Services, \%Interfaces, \%Protocols, \@Rules, \$Id, \%Sysconfig, \%Marker);
		}
		if ($writeconfigfile) {
			writeConfig ($writeconfigfile, \%Networks, \%Services, \%Interfaces, \%Protocols, \@Rules, \%Sysconfig, \%Marker);
			exit 0;
		} elsif ($writeldap) {
			writeLdap ($ldap, $ldapbase, $writeldapruleset, \%Networks, \%Services, \%Interfaces, \%Protocols, \@Rules, \%Sysconfig, \%Marker);
			exit 0;
		} else {
			validateData (\%Networks, \%Services, \%Interfaces, \%Protocols, \@Rules, \%Sysconfig, \%Marker);
			if ($Sysconfig{'filtercommand'} eq 'nft') {
				genRuleDump_NFT (\@Rules, \@Listing, \%Sysconfig);
			} else {
				genRuleDump_IPTABLES (\@Rules, \@Listing, \%Sysconfig);
			}
		}
	} else {
		validateSysconfig (\%Sysconfig);
		if ($Sysconfig{'filtercommand'} eq 'nft') {
			clearAllRules_NFT (\@Listing);
		} else {
			clearAllRules_IPTABLES (\@Listing);
		}
	}

	if ($print) {
		printRules (\@Listing);
	}
	if ($test==0) {
		if ($Sysconfig{'filtercommand'} eq 'nft') {
			applyRules_NFT ($timeout, \@Listing, \%Sysconfig);
		} else {
			applyRules_IPTABLES ($timeout, \@Listing, \%Sysconfig);
		}
	}
}

sub clearAllRules_NFT {
	my ($Listing) = @_;

	if ($ipv6) {
		push (@$Listing,"flush ruleset ip6");
	} else {
		push (@$Listing,"flush ruleset ip");
	}
}

sub clearAllRules_IPTABLES {
	my ($Listing) = @_;

	push (@$Listing,"*mangle");
	push (@$Listing, ":PREROUTING ACCEPT [0:0]");
	push (@$Listing, ":OUTPUT ACCEPT [0:0]");
	push (@$Listing, "COMMIT");
	if ($ipv6) {} else {
		push (@$Listing, "*nat");
		push (@$Listing, ":PREROUTING ACCEPT [0:0]");
		push (@$Listing, ":POSTROUTING ACCEPT [0:0]");
		push (@$Listing, ":OUTPUT ACCEPT [0:0]");
		push (@$Listing, "COMMIT");
	}
	push (@$Listing, "*filter");
	push (@$Listing, ":INPUT ACCEPT [0:0]");
	push (@$Listing, ":OUTPUT ACCEPT [0:0]");
	push (@$Listing, ":FORWARD ACCEPT [0:0]");
	push (@$Listing, "COMMIT");
}

sub uifUsg {
	print "usage: $0 [-6] [-c configfile] [-t] [-p] [-d] [-s server] [-b base] [-r ruleset] [-R ruleset] [-D <bind dn>] [-W] [-w <password>] [-T time] [-C configfile]\n";
	print "-6  ipv6 mode default config $configfile6\n";
	print "-c  read <configfile> instead of $configfile (or in ipv6 mode $configfile6)\n";
	print "-t  test rules\n";
	print "-p  print rules to stdout\n";
	print "-d  disable firewall (clear all rules)\n";
	print "-s  LDAP-server (default: localhost)\n";
	print "-b  LDAP-base\n";
	print "-r  LDAP ruleset\n";
	print "-T  apply new rules and restore old rules after <time> seconds\n";
	print "-C  write previously read config to <configfile>\n";
	print "-R  write previously read config to LDAP as <ruleset>\n";
	print "-D  LDAP bind DN\n";
	print "-w  use <password> during LDAP bind\n";
	print "-W  ask for password for LDAP bind\n";

	exit 0;
}

sub cleanupLdap {
	my ($ldap, $ldapbase) = @_;
	my $mesg;

	$mesg = $ldap->search (	base => "ou=Filter,ou=Sysconfig,$ldapbase",
				filter => "objectClass=UIFRuleSet");
	if ($mesg->is_error || $mesg->count == 0) {
		die "ldapsearch failed\n";
	}

	my $result;
	$result=$mesg->as_struct;
	my %fwruleset;
	my $entry;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		foreach (@{$$arrayref{'uiflist'}}) {
			foreach (split (/\s+/, $_)) {
				$_ eq '' && next;
				$fwruleset{$_}=1;
			}
		}
	}

	$mesg = $ldap->search (	base => "ou=Filter,ou=Sysconfig,$ldapbase",
				filter => "objectClass=UIFRule");
	if ($mesg->is_error || $mesg->count == 0) {
		die "ldapsearch failed\n";
	}
	$result=$mesg->as_struct;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		foreach (@{$$arrayref{'cn'}}) {
			unless (exists($fwruleset{$_})) {
				$mesg = $ldap->delete($entry);
				if ($mesg->is_error) {
					die "ldapsearch failed\n";
				}
			}
		}
	}
}

sub readLdap {
	my ($ldap, $ldapbase, $ldapruleset, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Sysconfig, $Marker) = @_;
	my $mesg;

	$mesg = $ldap->search (	base => "ou=Filter,ou=Sysconfig,$ldapbase",
				filter => "(\&(objectClass=UIFRuleSet) (cn=$ldapruleset))");
	if ($mesg->is_error || $mesg->count != 1) {
		die "ldapsearch failed\n";
	}

	my $result;
	$result=$mesg->as_struct;
	my %fwruleset;
	my %fwdisabled;
	my $counter=0;
	my $entry;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		foreach (@{$$arrayref{'uifdisabled'}}) {
			foreach (split (/\s+/, $_)) {
				$_ eq '' && next;
				$fwdisabled{$_}=1;
			}
		}
		foreach (@{$$arrayref{'uiflist'}}) {
			foreach (split (/\s+/, $_)) {
				$_ eq '' && next;
				unless (exists($fwdisabled{$_})) {
					$fwruleset{$_}=$counter++;
				}
			}
		}
		my $sysentry;
		foreach $sysentry (qw(LogLevel LogPrefix LogLimit LogBurst Limit Burst AccountPrefix)) {
			if (@{$$arrayref{"UIF".$sysentry}}[0]) {
				$$Sysconfig{$sysentry}=@{$$arrayref{"UIF".$sysentry}}[0];
			}
		}
	}

	$mesg = $ldap->search (	base => $ldapbase,
				filter => "objectClass=ipNetwork");
	if ($mesg->is_error) {
		die "ldapsearch (network) failed\n";
	}
	$result=$mesg->as_struct;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		my $name = @{$$arrayref{'cn'}}[0];
		my $netaddress = @{$$arrayref{'ipnetworknumber'}}[0];
		my $netmask = @{$$arrayref{'ipnetmasknumber'}}[0];
		die "undefined netmask\n" unless defined($netmask);
		$$Networks{$name}.="$netaddress/$netmask ";
	}

	$mesg = $ldap->search (	base => $ldapbase,
				filter => "objectClass=ipHost");
	if ($mesg->is_error) {
		die "ldapsearch (iphost) failed\n";
	}
	$result=$mesg->as_struct;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		my $name = @{$$arrayref{'cn'}}[0];
		my $hostaddress = @{$$arrayref{'iphostnumber'}}[0];
		if (exists($$arrayref{'macaddress'})) {
			$$Networks{$name}.="$hostaddress/32=@{$$arrayref{'macaddress'}}[0] ";
		} else {
			$$Networks{$name}.="$hostaddress/32 ";
		}
	}

	$mesg = $ldap->search (	base => "ou=Filter,ou=Sysconfig,$ldapbase",
				filter => "objectClass=UIFGroup");
	if ($mesg->is_error) {
		die "ldapsearch (group) failed\n";
	}
	$result=$mesg->as_struct;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		my $name = @{$$arrayref{'cn'}}[0];
		if (exists($$arrayref{'uifnetwork'})) {
			$$Networks{$name}.=join (" ", @{$$arrayref{'uifnetwork'}})." ";
		}
		if (exists($$arrayref{'uifservice'})) {
			$$Services{$name}.=join (" ", @{$$arrayref{'uifservice'}})." ";
		}
		if (exists($$arrayref{'uifdevice'})) {
			$$Interfaces{$name}.=join (" ", @{$$arrayref{'uifdevice'}})." ";
		}
		if (exists($$arrayref{'uifmark'})) {
			$$Marker{$name}.=join (" ", @{$$arrayref{'uifmark'}})." ";
		}
	}

	$mesg = $ldap->search (	base => $ldapbase,
				filter => "objectClass=ipProtocol");
	if ($mesg->is_error) {
		die "ldapsearch (protocol) failed\n";
	}
	$result=$mesg->as_struct;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		my $name = @{$$arrayref{'cn'}}[0];
		my $number = @{$$arrayref{'ipprotocolnumber'}}[0];
		$$Protocols{$name}=$number;
		$$Protocols{$number}=$name;
	}

	$mesg = $ldap->search (	base => "ou=Filter,ou=Sysconfig,$ldapbase",
				filter => "objectClass=UIFRule");
	if ($mesg->is_error) {
		die "ldapsearch (rule) failed\n";
	}
	$result=$mesg->as_struct;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		my $name = @{$$arrayref{'cn'}}[0];
		if (exists($fwruleset{$name})) {
			my $type=@{$$arrayref{'uiftype'}}[0];
			my %temphash;
			$temphash{'Id'} = $name;
			if ($type =~ /^\s*(\w+([-+|>]|{\w+}))$/) {
				my $type = $1;
				$temphash{'Type'}=$type;
			} else {
				die "invalid ruletype: $type\n";
			}
			my $entry;
			foreach $entry (keys(%ldapstringmap)) {
				if (exists($$arrayref{$entry})) {
					foreach (@{$$arrayref{$entry}}) {
						$temphash{$ldapstringmap{$entry}}.="$_ ";
					}
				}
			}
			$$Rules[$fwruleset{$name}]=\%temphash;
		}
	}
}

sub writeLdap {
	my ($ldap, $ldapbase, $writeldapruleset, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Sysconfig, $Marker) = @_;

	validateSysconfig $Sysconfig;

	my $mesg;
	my $ruleset;

	$mesg = $ldap->search (	base => "ou=Filter,ou=Sysconfig,$ldapbase",
				filter => "objectClass=UIFRule");
	if ($mesg->is_error) {
		die "ldapsearch failed\n";
	}

	my $counter;
	my $result;
	$result=$mesg->as_struct;

	my $cn;
	my $maxcn=0;
	my $entry;
	foreach $entry (keys (%$result)) {
		my $arrayref = $$result{$entry};
		$cn=@{$$arrayref{'cn'}}[0];
		if ($cn =~ /^\d+$/) {
			if ($cn > $maxcn) {
				$maxcn=$cn;
			}
		}
	}
	my $cns;

	my $rule;
	foreach $rule (@$Rules) {
		$cns.=++$maxcn." ";

		my @ruleentry = ("cn", "$maxcn", "objectClass", "UIFRule");
		my $key;
		foreach $key (keys %$rule) {
			exists($ldapwritemap{$key}) || next;
			my @entries;
			foreach $entry (split (/\s+/, $$rule{$key})) {
				$entry eq '' && next;
				push (@entries, $entry);
			}
			push (@ruleentry, $ldapwritemap{$key});
			push (@ruleentry, \@entries);
		}
		addLdap ($ldap, "cn=$maxcn,ou=Rules,ou=Filter,ou=Sysconfig,$ldapbase", \@ruleentry);
	}

	if ($cns) {
		my @ruleset = ("cn", "$writeldapruleset", "objectClass", "UIFRuleSet");
		push (@ruleset, 'UIFList');
		push (@ruleset, $cns);

		my $syskeys;
		foreach $syskeys (keys %$Sysconfig) {
			push (@ruleset, "UIF$syskeys");
			push (@ruleset, $$Sysconfig{$syskeys});
		}
		addLdap ($ldap, "cn=$writeldapruleset,ou=RuleSets,ou=Filter,ou=Sysconfig,$ldapbase", \@ruleset);
	}
	my $network;
	foreach $network (keys (%$Networks)) {
		my $counter="";
		my @entry;
		my @networks;
		my $nethost;

		foreach $nethost (split (/\s+/, $$Networks{$network})) {
			$nethost eq '' && next;

			$nethost =~ s/\/32//g;
			$nethost =~ s/\/255.255.255.255//g;
			if ($nethost =~ /\//) {
				@entry = ("cn", "$network$counter", "objectClass", "ipNetwork");
				my $ip;
				if ($ipv6) {
					$ip = NetAddr::IP->new6($nethost) || die "not a valid network: $nethost\n";
				} else {
					$ip = NetAddr::IP->new($nethost) || die "not a valid network: $nethost\n";
				}
				push (@entry, "ipNetworkNumber");
				push (@entry, $ip->addr());
				push (@entry, "ipNetmaskNumber");
				push (@entry, $ip->mask());
				addLdap ($ldap, "cn=$network$counter,ou=Networks,$ldapbase", \@entry);
				push (@networks, "$network$counter");
				if ($counter) {
					$counter++;
				} else {
					$counter=1;
				}
			} elsif ($nethost =~ /[.]/) {
				@entry = ("cn", "$network$counter", "objectClass", [ 	"ipHost",
										"ieee802device",
										"device" ]);
				my $ip;
				my $mac;
				if ($nethost =~ /^(.+)=(.+)$/) {
					$mac=$2;
					if ($ipv6) {
						$ip = NetAddr::IP->new6($1) || die "not a valid network: $1\n";
					} else {
						$ip = NetAddr::IP->new($1) || die "not a valid network: $1\n";
					}
				} else {
					if ($ipv6) {
						$ip = NetAddr::IP->new6($nethost) || die "not a valid network: $nethost\n";
					} else {
						$ip = NetAddr::IP->new($nethost) || die "not a valid network: $nethost\n";
					}
				}
				push (@entry, "ipHostNumber");
				push (@entry, $ip->addr());
				if ($mac) {
					push (@entry, "macAddress");
					push (@entry, $mac);
				}
				addLdap ($ldap, "cn=$network$counter,ou=Hosts,$ldapbase", \@entry);
				push (@networks, "$network$counter");
				if ($counter) {
					$counter++;
				} else {
					$counter=1;
				}
			} else {
				push (@networks, $nethost);
			}
		}
		if ($#networks > 0) {
			@entry = ("cn", "$network", "objectClass", "UIFGroup", "UIFNetwork", \@networks);
			addLdap ($ldap, "cn=$network,ou=NetGroups,ou=Filter,ou=sysconfig,$ldapbase", \@entry);
		}
	}

	my $service;
	foreach $service (keys (%$Services)) {
		my @entry;
		my $serviceentry;
		@entry = ("cn", $service, "objectClass", "UIFGroup");
		my @services;
		foreach $serviceentry (split (/\s+/, $$Services{$service})) {
			$serviceentry eq '' && next;
			push (@services, $serviceentry);
		}
		push (@entry, "UIFService");
		push (@entry, \@services);
		addLdap ($ldap, "cn=$service,ou=Services,ou=Filter,ou=sysconfig,$ldapbase", \@entry);
	}

	my $interface;
	foreach $interface (keys (%$Interfaces)) {
		my @entry;
		my $interfaceentry;
		@entry = ("cn", $interface, "objectClass", "UIFGroup");
		my @interfaces;
		foreach $interfaceentry (split (/\s+/, $$Interfaces{$interface})) {
			$interfaceentry eq '' && next;
			push (@interfaces, $interfaceentry);
		}
		push (@entry, "UIFDevice");
		push (@entry, \@interfaces);
		addLdap ($ldap, "cn=$interface,ou=Interfaces,ou=Filter,ou=sysconfig,$ldapbase", \@entry);
	}

	my $marker;
	foreach $marker (keys (%$Marker)) {
		my @entry;
		my $markerentry;
		@entry = ("cn", $marker, "objectClass", "UIFGroup");
		my @markervalues;
		foreach $markerentry (split (/\s+/, $$Marker{$marker})) {
			$markerentry eq '' && next;
			push (@markervalues, $markerentry);
		}
		push (@entry, "UIFMark");
		push (@entry, \@markervalues);
		addLdap ($ldap, "cn=$marker,ou=Marker,ou=Filter,ou=sysconfig,$ldapbase", \@entry);
	}

	cleanupLdap ($ldap, $ldapbase);
}

sub addLdap {
	my ($ldap, $dn, $attr) = @_;
	my $mesg;

	$ldap->delete ($dn);

	$mesg = $ldap->add (	$dn,
				attr => $attr
			   );

	if ($mesg->is_error) {
		die "adding rule failed: ".$mesg->error."\n";
	}
}

sub writeConfig {
	my ($configfile, $Networks, $Services, $Interfaces, $Protocols, $Rules, $Sysconfig, $Marker) = @_;

	-e $configfile && die "$configfile already exists\n";
	open (OUTFILE, ">$configfile") || die "can't open $configfile\n";
	print OUTFILE "sysconfig {\n";
	foreach (keys (%$Sysconfig)) {
		print OUTFILE "\t$_\t$$Sysconfig{$_}\n";
	}
	print OUTFILE "}\n";
	print OUTFILE "service {\n";
	foreach (keys (%$Services)) {
		print OUTFILE "\t$_\t$$Services{$_}\n";
	}
	print OUTFILE "}\n";
	print OUTFILE "network {\n";
	foreach (keys (%$Networks)) {
		print OUTFILE "\t$_\t$$Networks{$_}\n";
	}
	print OUTFILE "}\n";
	print OUTFILE "interface {\n";
	foreach (keys (%$Interfaces)) {
		print OUTFILE "\t$_\t$$Interfaces{$_}\n";
	}
	print OUTFILE "}\n";
	print OUTFILE "marker {\n";
	foreach (keys (%$Marker)) {
		print OUTFILE "\t$_\t$$Marker{$_}\n";
	}
	print OUTFILE "}\n";
	print OUTFILE "filter {\n";
	my $rule;
	foreach $rule (@$Rules) {
		print OUTFILE "\t${$rule}{'Type'}";
		my $entry;
		foreach $entry (@mapping) {
			my $key=$$entry[2];
			if (exists($$rule{$key}) && $$entry[0] ne '') {
				my $char=$$entry[0];
				my $value=${$rule}{$key};
				$value =~ s/^\s+//;
				$value =~ s/\s+$//;
				$value =~ s/\s+/ /g;
				$value =~ tr/ /,/;
				print OUTFILE "\t$char=$value";
			}
		}
		print OUTFILE "\n";
	}
	print OUTFILE "}\n";
}

readCommandLine();
