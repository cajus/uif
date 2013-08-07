## IPv6 network name definitions for UIF
#  In the network section you're asked to provide informations on all
#  IPv6 hosts and/or networks running in your setup.
#
#  syntax: net_name [ip-address[=mac-address]] [network] [net_name]
#  examples: webserver 2001:610:1908:b000::148:14
#            intranet  fd00:0:0:1::/64
#            dmz       fd00:0:0:5::/64
#            some      intranet dmz fd00:0:2:1::1
#            router    fd00:0:0:1::1=0A:32:F2:C7:1A:31

network {
    localhost   ::1
    all         ::/0
#   trusted     fd00:1:2:3::/64
}
