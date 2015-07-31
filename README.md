# OVERVIEW

This is an application that would enable on demand troubleshooting of a DC fabric running Nexus switches, by taking in a 5 tuple and tracing the path of this flow across the network. 

It can be executed on a switch or on a standalone host that has a Python execution engine, i.e. Linux, MAC, Windows

----

There will be two modes to run the script:

* mode=auto (does not prompt user to continue)
* mode=interactive (prompts user to continue during the trace)

Use `argparse` and include params for:

* user
* pwd
* src
* dest
* proto
* src_port
* dest_port
* ingress (default=X/Y as it doesn't seem to be a requirement)
* vrf
* mode (default=interactive)
* target (ip address of switch where trace will start)

Device credentials should also be able to be stored in a conf file.  If the conf file does not exist and they are not provided via command line, then interactively ask the user when the script starts for one set of credentials (should use `getpass`), so passwords are not displayed on the screen.  If `getpass` does not exist, which it may not, if it's being run on the Nexus switch, it should still allow a password to be entered, but visible in clear text.

If the argparse args are not provided via the command line, then ask the user to enter the required parameters (that are still needed).  Want to make this fool proof.

---

This is the expected sample output during execution of the FlowTracker application:

```
FLOW  SRC: `src` DEST: `dest` PROTO: `proto` SRC_PORT: `src_port` DEST_PORT: `dest_port` IN: `ingress` VRF: `vrf`

#############################################################################

NODE: <ip address of switch entered by user>

LOAD_SHARE_MODE:
VRF:
IN_IF:
OUT_IF:
DEST:
NEXT_HOP:
COUNTERS:

IN_IF:
  CRC:
  DROPS:
  RESETS:

OUT_IF:
  CRC:
  DROPS:
  RESETS:

Hit Enter to Continue...

NODE: <ip address of previous next-hop>

LOAD_SHARE_MODE:
VRF:
IN_IF:
OUT_IF:
DEST:
NEXT_HOP:
COUNTERS:

IN_IF:
  CRC:
  DROPS:
  RESETS:

OUT_IF:
  CRC:
  DROPS:
  RESETS:


Hit Enter to Continue...

...should continue until the neighbor is not a physical Nexus switch or the destination is physically plugged into the switch...

```


## Notes

show routing hash 10.10.10.2 2.2.2.2 ip-proto 17 8500 8700 in-interface eth4/51

Get these params:
-   load_share_mode
-   vrf
-   out_if
-   dest
-   next-hop

Get counters, errors, crs, drops, etc. for the “outgoing” interface

We also need to check incoming interface to figure out where the source is, so we’ll need to do: 

‘show ip arp <src>’

Get the interface it’s seen on and it’s MAC address.

Now get counters, errors, crs, drops, etc. for this “incoming” interface
