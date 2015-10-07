# Flowtracker Overview

This script enables on demand troubleshooting of a DC fabric running Nexus switches, by taking in a 5-tuple and tracing the path of this flow across the network.

It can be executed on any standalone host with Python installed (e.g. Linux, Mac, or Windows).

It **requires** the external python libraries, ``pycsco`` and ``netmiko``, but these can be installed automatically using the installation instructions below.

# Installation
(syntax below for Linux/Mac, but analogous steps for Windows)

## via ``pip``:

If your host has ``pip`` installed, you can simply do:
```
sudo pip install flowtracker
```

## by cloning this repository:
```
git clone https://github.com/networktocode/flowtracker.git
cd flowtracker
sudo python setup.py install
```

Both methods install an executable on the host's system path so that the script can be executed by simply typing ``flowtracker`` from the command prompt.

# Usage

## Script arguments

The arguments given to the script supply information about the flow to track, and the Nexus switches to contact. All arguments can be supplied either via command line flags, or by interactive prompt to the user. If an argument isn't supplied by a flag, the user will be prompted for that argument. A special flag `-h` or `--help` prints a description about each of the other arguments and how to use them as command line flags. Below is the output from running ``flowtracker -h``.
```
usage: flowtracker  [-h] [--src SRC] [--dest DEST] [--proto PROTO]
                    [--target TARGET] [--user USER] [--pwd PWD]
                    [--src_port SRC_PORT] [--dest_port DEST_PORT]
                    [--vrf VRF] [--mode {interactive,auto}] [--use_mgmt]

optional arguments:
  -h, --help            show this help message and exit
  --src SRC             The source IP address or hostname of the flow.
  --dest DEST           The destination IP address or hostname of the flow.
  --proto PROTO         The IP protocol number. Common names like icmp, tcp,
                        and udp may be used.
  --target TARGET       The IP address or hostname of the switch to start the
                        flow track.
  --user USER           The SSH/NXAPI username for the switch.
  --pwd PWD             The SSH/NXAPI password for the switch.
  --src_port SRC_PORT   The source layer 4 port of the flow.
  --dest_port DEST_PORT
                        The destination layer 4 port of the flow.
  --vrf VRF             The VRF of the flow.
  --mode {interactive,auto}
                        Interactive mode prompts the user to continue at each
                        hop.
  --use_mgmt            Use the Management IP address to connect to each hop.
                        Uses the NXAPI instead of SSH.
```

The ``--mode`` argument, which can only be supplied as a command line flag, provides two modes to run the script, ``interactive``(default) and ``auto``. ``interactive`` will prompt the user to Enter to continue to next hop, at each hop in the path, after printing flow information. ``auto`` will automatically move on to each hop.

The ``--use_mgmt`` flag, if set, instructs the script to connect to each switch on its management interface. If it is not set, the script uses the next hop IP address, learned at each hop, to connect to the next hop. A side effect of setting this flag is that the script attempts to use NX-API, with SSH as fall back. If the flag isn't set, the script only uses SSH. Using NX-API yields dramatic speed improvements in the running time of the script.

Like most other arguments, if the SSH/NXAPI password (``--pwd``) isn't supplied via a command line flag, the user is prompted for it. When the user types at the prompt, the password is not displayed on screen. However if ``--pwd`` is supplied via command line flag, the password is displayed on screen.

## Running the script:

Below is an example runing the script with a combination of command line flags and prompts. ``--mode``, ``--use_mgmt``, ``--target``, and ``--user`` are supplied via command line flags. The flow's *source IP*, *destination IP*, *source port*, *destination port*, *IP protocol* are supplied by responding to prompts. Likewise are the *password*, and *vrf*. The *password* is hidden, and the optional **vrf** argument is not supplied.

Initial execution:
```
flowtracker --mode auto --use_mgmt --target p9372-1 --user cisco
```

Prompts:
```
Enter source IP of the flow: 3.3.3.3
Enter destination IP of the flow: 4.4.4.4
Enter IP protocol(tcp, udp, icmp, <number>): tcp
SSH/NXAPI Password:
(Optional) TCP/UDP Source Port: 1234
(Optional) TCP/UDP Destination Port: 80
(Optional) VRF of the flow:
```
Below is the output of the script given the above input. First a FLOW OVERVIEW is displayed, recapping the inputs given. Then, the output at each hop in the path is displayed and separated by a line of #'s. 

At each hop, we see which hop we are CONNECTED TO, its HOP NUMBER, and the LOAD_SHARE_MODE. We also see the outgoing interface of the flow in OUT_IF, and the NEXT_HOP. At the bottom, interface statistics about the OUT_IF are displayed:

```
FLOW OVERVIEW:

SRC: 3.3.3.3
DEST: 4.4.4.4
PROTO: 6
SRC_PORT: 1234
DEST_PORT: 80
VRF: default


#############################################################################

CONNECTED TO: 9372-1 (p9372-1)
HOP NUMBER: 1

LOAD_SHARE_MODE: address source-destination port source-destination
VRF: default
OUT_IF: Eth1/52
DEST: 4.4.4.4
NEXT_HOP: 10.10.60.1

OUT_IF:
  RESETS: 6
  TX_STATS:
    1552 unicast packets  233683 multicast packets  3 broadcast packets
    235246 output packets  24675632 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause




Elapsed Time for Hop: 1.347575 seconds.

#############################################################################

CONNECTED TO: N9K2 (10.10.60.1)
HOP NUMBER: 2

LOAD_SHARE_MODE: address source-destination port source-destination
VRF: default
OUT_IF: Eth2/3
DEST: 4.4.4.4
NEXT_HOP: 10.10.70.2

OUT_IF:
  RESETS: 2
  TX_STATS:
    81 unicast packets  27053 multicast packets  3 broadcast packets
    27150 output packets  3490279 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  0 output discard
    0 Tx pause




Elapsed Time for Hop: 4.153353 seconds.

#############################################################################

CONNECTED TO: 9372-2 (10.10.70.2)
HOP NUMBER: 3

LOAD_SHARE_MODE: address source-destination port source-destination
VRF: default
OUT_IF: sup-eth1 , local, attached
DEST: 4.4.4.4
NEXT_HOP: sup-eth1

OUT_IF:
  RESETS: N/A
  TX_STATS: N/A


Elapsed Time for Hop: 0.192762 seconds.
```
