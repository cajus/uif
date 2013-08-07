## IPv4 network name definitions for UIF
#  In the network section you're asked to provide informations on all
#  IPv4 hosts and/or networks running in your setup.
#
#  syntax: net_name [ip-address[=mac-address]] [network] [net_name]
#  examples: webserver 192.168.1.5
#            intranet  10.1.0.0/16
#            dmz       10.5.0.0/255.255.0.0
#            some      intranet dmz 10.2.1.1
#            router    10.1.0.1=0A:32:F2:C7:1A:31

network {
    localhost   127.0.0.1
    all         0.0.0.0/0
#   trusted     192.168.1.0/24
}
