#!/bin/bash

tmpresults_nft="$(mktemp)"
tmpresults_iptables="$(mktemp)"

sudo nft flush ruleset ip

sudo FILTER_COMMAND=nft ./uif.pl
sudo nft list ruleset ip 1> "${tmpresults_nft}"
sudo nft flush ruleset ip

sudo FILTER_COMMAND=iptables-nft ./uif.pl
sudo nft list ruleset ip 1> "${tmpresults_iptables}"
#sudo nft flush ruleset ip

diff -wu "${tmpresults_iptables}" "${tmpresults_nft}"
