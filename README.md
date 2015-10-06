# OVERVIEW

This application enables on demand troubleshooting of a DC fabric running Nexus switches, by taking in a 5 tuple and tracing the path of this flow across the network.

It can be executed on a switch or on a standalone host that has a Python execution engine, i.e. Linux, MAC, Windows.

It uses the external python libraries, ``pycsco`` and ``netmiko``.

----

There are two modes to run the script:

* mode=auto (does not prompt user to continue)
* mode=interactive (prompts user to continue during the trace)

* user
* pwd
* src
* dest
* proto
* src_port (optional)
* dest_port (optional)
* vrf (optional)
* mode (default=interactive)
* target (ip address of switch where trace will start)

---

Sample Input:
```
python flowtracker.py --mode auto --use_mgmt --target p9372-1 --user cisco
Enter source IP of the flow: 3.3.3.3
Enter destination IP of the flow: 4.4.4.4
Enter IP protocol(tcp, udp, icmp, <number>): tcp
SSH/NXAPI Password:
(Optional) TCP/UDP Source Port:
(Optional) TCP/UDP Destination Port:
(Optional) VRF of the flow:
```

Sample Output:
```
FLOW OVERVIEW:

SRC: 3.3.3.3
DEST: 4.4.4.4
PROTO: 6
SRC_PORT: N/A
DEST_PORT: N/A
VRF: default


#############################################################################

CONNECTED TO: 9372-1 (p9372-1)
HOP NUMBER: 1

LOAD_SHARE_MODE: address source-destination port source-destination
VRF: default
OUT_IF: Eth1/51
DEST: 4.4.4.4
NEXT_HOP: 10.10.20.1

OUT_IF:
  RESETS: 7
  TX_STATS:
    78 unicast packets  6973 multicast packets  5 broadcast packets
    7058 output packets  734811 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause




Elapsed Time for Hop: 0.416023 seconds.

#############################################################################

CONNECTED TO: N9K1.cisconxapi.com (10.10.20.1)
HOP NUMBER: 2

LOAD_SHARE_MODE: address source-destination port source-destination
VRF: default
OUT_IF: Eth2/4
DEST: 4.4.4.4
NEXT_HOP: 10.10.40.2

OUT_IF:
  RESETS: 5
  TX_STATS:
    1639 unicast packets  283955 multicast packets  10 broadcast packets
    285610 output packets  39540648 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause




Elapsed Time for Hop: 1.921894 seconds.

#############################################################################

CONNECTED TO: 9372-2 (10.10.40.2)
HOP NUMBER: 3

LOAD_SHARE_MODE: address source-destination port source-destination
VRF: default
OUT_IF: sup-eth1 , local, attached
DEST: 4.4.4.4
NEXT_HOP: sup-eth1

OUT_IF:
  RESETS: N/A
  TX_STATS: N/A


Elapsed Time for Hop: 0.19492 seconds.
```
