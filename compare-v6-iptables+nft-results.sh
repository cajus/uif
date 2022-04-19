#!/bin/bash

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
