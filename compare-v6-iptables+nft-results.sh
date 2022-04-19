#!/bin/bash

# Copyright (C) 2013-2022 Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
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

# this script requires /etc/uif/ to be in place and configured well

tmpresults_nft="$(mktemp)"
tmpresults_iptables="$(mktemp)"

sudo nft flush ruleset ip6

sudo FILTER_COMMAND=nft ./uif.pl -6
sudo nft list ruleset ip6 1> "${tmpresults_nft}"
sudo nft flush ruleset ip6

sudo FILTER_COMMAND=iptables-nft ./uif.pl -6
sudo nft list ruleset ip6 1> "${tmpresults_iptables}"
#sudo nft flush ruleset ip6

diff -wu "${tmpresults_iptables}" "${tmpresults_nft}"
