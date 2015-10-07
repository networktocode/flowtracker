"""This script/module tracks the hop-by-hop path for a flow through
Nexus switches, and gives interface statistics for each outgoing interface.
"""
import argparse
import socket
import sys
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from netmiko import ConnectHandler
from getpass import getpass
from pycsco.nxos.device import Device as PYCSCO

SSH_TYPE = 'ssh'
PYCSCO_TYPE = 'pycsco'


class HashError(Exception):
    """Error raised when flow's hash can't be computed.
    """
    def __init__(self, hash_output):
        self.hash_output = hash_output


class Device(object):
    """Base class for SSH (paramiko) and NXAPI (pycsco)
       devices.
    """
    def __init__(self, device_type):
        self.device_type = device_type

    def get_instance(self, hostname, username, password):
        """Return an instance of child class depending on device_type.
        """
        if self.device_type == SSH_TYPE:
            return SshDevice(hostname, username, password)
        elif self.device_type == PYCSCO_TYPE:
            nxos_device = PycscoDevice(hostname, username, password)
            try:
                nxos_device.show_command('sh version')
            except Exception:
                print 'NXAPI not found on device {}, attempting SSH.'.format(hostname)
                return SshDevice(hostname, username, password)

            return nxos_device

    def show_command(self, cmd):
        """Base method for returning output from a show command.
        """
        raise NotImplementedError

    def disconnect(self):
        """Base method for tearing down a connection.
        """
        raise NotImplementedError


class SshDevice(Device):
    """Class for communicating with switches over SSH.
    """
    def __init__(self, hostname, username, password):
        try:
            self.device = ConnectHandler(
                device_type='cisco_nxos',
                ip=hostname,
                username=username,
                password=password,
                verbose=False
            )
        except:
            print 'Error SSHing to device at {}'.format(
                hostname)
            print 'This may not be a Cisco device, or there may an authentication issue.'
            sys.exit()

    def show_command(self, cmd):
        if not self.device.check_enable_mode():
            self.device.enable()
        return self.device.send_command(cmd)

    def disconnect(self):
        self.device.disconnect()


class PycscoDevice(Device):
    """Class for communicating with switches over NXAPI.
    """
    def __init__(self, hostname, username, password):
        self.device = PYCSCO(username, password, hostname)

    def show_command(self, cmd):
        xml_rsp = self.device.show(cmd, text=True)
        root = ET.fromstring(xml_rsp[1])
        body = root.find('.//body').text
        return body

    def disconnect(self):
        pass


def convert_proto(proto):
    """Convert a common protocol name to a protocol number.
    """
    convert_dict = {'icmp': '1',
                    'tcp': '6',
                    'udp': '17'}

    return convert_dict.get(proto, proto)


def _get_raw_hash_info(device, src, dest, **kwargs):
    """Get output of 'show routing hash' command.
    """
    cmd_str = 'show routing hash {} {}'.format(
        src, dest)

    ip_proto = kwargs.get('ip_proto')
    if ip_proto:
        cmd_str += ' ip-proto {}'.format(ip_proto)

    src_port = kwargs.get('src_port')
    if src_port:
        cmd_str += ' {}'.format(src_port)

    dest_port = kwargs.get('dest_port')
    if dest_port:
        cmd_str += ' {}'.format(dest_port)

    vrf = kwargs.get('vrf')
    if vrf:
        cmd_str += ' {}'.format(vrf)

    raw_hash_info = device.show_command(cmd_str)
    return str(raw_hash_info)


def get_hash_info(device, src, dest, **kwargs):
    """Get hash info from switch.

    Keyword Args:
        source (str):
        dest (str):
        proto (str): optional
        src_port (str): optional
        dest_port (str): optional
        vrf (str): optional

    Returns:
        A dictionary of parameters.
        Including::

            load_share_mode\n
            vrf\n
            out_if\n
            next_hop\n
    """
    hash_info = {}
    raw_info = _get_raw_hash_info(device, src, dest, **kwargs)

    match = re.search('Hash for VRF\s+"?(\w+)"?', raw_info)
    if not match:
        raise HashError(raw_info)

    hash_info['vrf'] = match.group(1)

    match = re.search('load-share mode: (\w.+)', raw_info)
    hash_info['load_share_mode'] = match.group(1)

    match = re.search('Out Interface: (\w.+)', raw_info)
    if match:
        hash_info['out_if'] = match.group(1)

    match = re.search('Hashing to path (\*?(\d|\.)+)', raw_info)
    if not match:
        match = re.search('Hashing to path (\*?.+)', raw_info)

    next_hop = match.group(1).strip('*')
    hash_info['next_hop'] = next_hop

    if dest == next_hop:
        mac = get_mac_from_ip(device, dest)
        hash_info['out_if'] = get_int_from_mac(device, mac)

    return hash_info


def _get_raw_iface_stats(device, iface_name):
    """Get 'show interface' output.
    """
    # if 'local' is in the name, don't attaempt show interface
    if 'local' in iface_name:
        return ''

    raw_stats = device.show_command('show interface {}'.format(iface_name))
    return str(raw_stats)


def get_iface_stats(device, iface_name):
    """Parse interface error and counter info.
    """
    iface_stats = {}
    raw_iface_info = _get_raw_iface_stats(device, iface_name)

    match = re.search('(\d+) interface resets', raw_iface_info)
    if match:
        iface_stats['resets'] = match.group(1)

    tx_info_split = raw_iface_info.split('TX')
    if len(tx_info_split) > 1:
        iface_stats['tx_counters'] = raw_iface_info.split('TX')[-1]

    return iface_stats


def get_mgmt(device, next_hop):
    """Try to glean the management IP address
    of the next hop using 'sh cdp neighbors detail'.
    """
    mgmt_ip = None
    cdp_raw = device.show_command('show cdp neighbors detail')
    lines = cdp_raw.splitlines()
    neighbor_found = False
    mgmt_found = False
    for line in lines:
        if next_hop in line:
            neighbor_found = True
            continue
        if neighbor_found:
            if 'Mgmt address' in line:
                mgmt_found = True
                continue
            if mgmt_found:
                if 'IPv4 Address' in line:
                    match = re.search('\d+.\d+.\d+.\d+', line)
                    if match:
                        mgmt_ip = match.group(0)
                        break
                    mgmt_found = False
            if '----------' in line:
                neighbor_found = False
                continue

    return mgmt_ip


def get_int_from_mac(device, mac):
    """Get an interface, given a MAC address from the CAM table.
    """
    mac_table_raw = device.show_command('show mac address-table')
    match = re.search(
        '{}\s+\w+\s+\d+\s+\w\s+\w\s+((\w|\d)+(\/\d+)?)'.format(mac), mac_table_raw)
    if match:
        return match.group(1)


def get_mac_from_ip(device, ip):
    """Get a MAC address, given an IP address from the ARP table.
    """
    arp_table_raw = device.show_command('show ip arp')
    match = re.search(
        '{}\s+\d+:\d+:\d+\s+(((\w|\d)+\.){{2}}(\w|\d)+)'.format(ip), arp_table_raw)
    return match.group(1)


def get_hostname(device):
    """Get the hostname of the device.
    """
    hostname = device.show_command('show hostname').strip()
    return hostname


def get_intro(args):
    """Intro message to script.
    """
    return """
FLOW OVERVIEW:

SRC: {}
DEST: {}
PROTO: {}
SRC_PORT: {}
DEST_PORT: {}
VRF: {}
""".format(args.src,
           args.dest,
           args.proto,
           args.src_port or 'N/A',
           args.dest_port or 'N/A',
           args.vrf or 'default')


def stringify(switch_ip, dest, hostname, hop_number, **hash_info):
    """Pretty print flow information.
    """
    return """
#############################################################################

CONNECTED TO: {} ({})
HOP NUMBER: {}

LOAD_SHARE_MODE: {}
VRF: {}
OUT_IF: {}
DEST: {}
NEXT_HOP: {}

OUT_IF:
  RESETS: {}
  TX_STATS: {}

""".format(hostname,
           switch_ip,
           hop_number,
           hash_info.get('load_share_mode'),
           hash_info.get('vrf'),
           hash_info.get('out_if'),
           dest,
           hash_info.get('next_hop'),
           hash_info.get('resets') or 'N/A',
           hash_info.get('tx_counters') or 'N/A')


def handle_args():
    """Parse command line arguments, and prompt user if they are not given.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--src',
                        help='The source IP address or hostname of the flow.')
    parser.add_argument('--dest',
                        help='The destination IP address or hostname of the flow.')
    parser.add_argument('--proto',
                        help='The IP protocol number.' +\
                        ' Common names like icmp, tcp, and udp may be used.')
    parser.add_argument('--target',
                        help='The IP address or hostname of the switch to start the flow track.')
    parser.add_argument('--user',
                        help='The SSH/NXAPI username for the switch.')
    parser.add_argument('--pwd',
                        help='The SSH/NXAPI password for the switch.')
    parser.add_argument('--src_port', help='The source layer 4 port of the flow.')
    parser.add_argument('--dest_port', help='The destination layer 4 port of the flow.')
    parser.add_argument('--vrf',
                        help='The VRF of the flow.')
    parser.add_argument('--mode',
                        choices=['interactive', 'auto'],
                        default='interactive',
                        help='Interactive mode prompts the user to continue at each hop.')
    parser.add_argument('--use_mgmt',
                        action='store_true',
                        help='Use the Management IP address to connect to each hop.\n'\
                             + 'Uses the NXAPI instead of SSH.')

    args = parser.parse_args()
    while not args.src:
        args.src = raw_input('Enter source IP of the flow: ')
        args.src = socket.gethostbyname(args.src)
    while not args.dest:
        args.dest = raw_input('Enter destination IP of the flow: ')
        args.dest = socket.gethostbyname(args.dest)
    while not args.proto:
        args.proto = raw_input('Enter IP protocol(tcp, udp, icmp, <number>): ')
        args.proto = convert_proto(args.proto)
    while not args.target:
        args.target = raw_input(
            'Enter IP or hostname of first switch to connect to: ')
        args.target = socket.gethostbyname(args.target)
    if args.use_mgmt is False:
        args.use_mgmt = None
    while args.use_mgmt is None:
        args.use_mgmt = args.use_mgmt or raw_input(
            'Use Management Interfaces for SSH[Y/N]: ')
        if args.use_mgmt.lower().startswith('y'):
            args.use_mgmt = True
        elif args.use_mgmt.lower().startswith('n'):
            args.use_mgmt = False
        else:
            args.use_mgmt = None
    while not args.user:
        args.user = raw_input('Enter the SSH/NXAPI username: ')
    while not args.pwd:
        args.pwd = getpass("SSH/NXAPI Password: ")

    if args.proto == '6' or args.proto == '17':
        args.src_port = args.src_port or raw_input('(Optional) TCP/UDP Source Port: ')
        args.dest_port = args.dest_port or raw_input('(Optional) TCP/UDP Destination Port: ')

    args.vrf = args.vrf or raw_input('(Optional) VRF of the flow: ')

    if bool(args.src_port) != bool(args.dest_port):
        print "--src_port and --dest_port must be supplied together."
        sys.exit()

    return args

def get_flow_info_string(args, device, hop_number, hash_info):
    """Get a string of flow information.
    """
    # Get the outgoing interface and statistics
    out_if = hash_info.get('out_if')
    iface_stats = get_iface_stats(device, out_if)
    hash_info.update(iface_stats)

    # Print out information for the flow on current hop
    hostname = get_hostname(device)
    output = stringify(args.target, args.dest, hostname, hop_number, **hash_info)

    return output


def query_switch(connect_ip, hop_number, args):
    """Query and print info from the switch.
    """
    # Decide whether to connect over NXAPI or SSH
    if args.use_mgmt:
        device_type = PYCSCO_TYPE
    else:
        device_type = SSH_TYPE

    device = Device(device_type).get_instance(
        connect_ip, args.user, args.pwd)

    # Get details of flow's hash on current switch.
    try:
        hash_info = get_hash_info(device,
                                  src=args.src,
                                  dest=args.dest,
                                  ip_proto=args.proto,
                                  src_port=args.src_port,
                                  dest_port=args.dest_port)
    except HashError as he:
        print 'Error at node {}'.format(args.target)
        print 'show routing hash output:'
        print he.hash_output
        sys.exit()

    # Get flow info an dprint it
    flow_info_string = get_flow_info_string(args, device, hop_number, hash_info)
    print flow_info_string

    return hash_info, device

def main():
    # Handle arguments and print introduction
    args = handle_args()
    intro = get_intro(args)
    print intro

    # Initialize loop conditional variables
    connect_ip = args.target
    out_if = 'unknown'
    hop_number = 1

    # When the next hop is the destination,
    # or when the next-hop is local to the switch,
    # the loop stops.
    while args.target != args.dest\
            and 'local' not in out_if:
        # Used later to calculate elapsed time
        starttime = datetime.now()

        # Query the switch
        hash_info, device = query_switch(connect_ip, hop_number, args)

        # Set up for next loop iteration
        args.target = hash_info.get('next_hop')
        out_if = hash_info.get('out_if')

        if args.use_mgmt:
            connect_ip = get_mgmt(device, args.target)
        else:
            connect_ip = args.target

        device.disconnect()
        hop_number += 1

        # Calculate and print elapsed time
        elapsed_time_delta = datetime.now() - starttime
        fraction = elapsed_time_delta.microseconds / 1000000.0
        elapsed_time = elapsed_time_delta.seconds + fraction

        print "Elapsed Time for Hop: " + str(elapsed_time) + " seconds."

        # In interactive mode, have the user hit Enter to continue
        if args.mode == 'interactive':
            loop = 'a'
            while loop:
                loop = raw_input("Hit Enter to Continue...")

if __name__ == "__main__":
    main()
