import argparse
import socket
import sys
import re
from netmiko import ConnectHandler
from getpass import getpass

class HashError(Exception):
    def __init__(self, hash_output):
        self.hash_output = hash_output

def convert_proto(proto):
    """Convert a common protocol name to a protocol number.
    """
    convert_dict = {'icmp': '1',
                    'tcp': '6',
                    'udp': '17'}

    return convert_dict.get(proto, proto)

def _get_raw_hash_info(device, src, dest, **kwargs):
    if not device.check_enable_mode():
        device.enable()

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

    raw_hash_info = device.send_command(cmd_str)
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
    raw_info = _get_raw_hash_info(device, src, dest, **kwargs)
    # TODO: get real info from switch
    hash_info = {}

    match = re.search('Hash for VRF "(\w+)"', raw_info)
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

def get_iface_stats(device, iface_name):
    """Parse interface error and counter info.
    """
    raw_iface_info = _get_raw_iface_stats(device, iface_name)

    iface_stats = {}

    match = re.search('(\d+) interface resets', raw_iface_info)
    if match:
        iface_stats['resets'] = match.group(1)

    tx_info_split = raw_iface_info.split('TX')
    if len(tx_info_split) > 1:
        iface_stats['tx_counters'] = raw_iface_info.split('TX')[-1]

    return iface_stats

def _get_raw_iface_stats(device, iface_name):
    """Get 'show interface' output.
    """
    if not device.check_enable_mode():
        device.enable()

    raw_stats = device.send_command('show interface {}'.format(iface_name))
    return str(raw_stats)

def get_mgmt(device, next_hop):
    """Try to glean the management IP address
    of the next hop using 'sh cdp neighbors detail'
    """
    if not device.check_enable_mode():
        device.enable()

    mgmt_ip = None
    cdp_raw = device.send_command('show cdp neighbors detail')
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
    if not device.check_enable_mode():
        device.enable()

    mac_table_raw = device.send_command('show mac address-table')
    match = re.search('{}\s+\w+\s+\d+\s+\w\s+\w\s+((\w|\d)+(\/\d+)?)'.format(mac), mac_table_raw)
    if match:
        return match.group(1)

def get_mac_from_ip(device, ip):
    if not device.check_enable_mode():
        device.enable()

    arp_table_raw = device.send_command('show ip arp')
    match = re.search('{}\s+\d+:\d+:\d+\s+(((\w|\d)+\.){{2}}(\w|\d)+)'.format(ip), arp_table_raw)
    return match.group(1)

def get_hostname(device):
    """Get the hostname of the device.
    """
    if not device.check_enable_mode():
        device.enable()
    hostname = device.send_command('show hostname').strip()
    return hostname

def intro(args):
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
    parser = argparse.ArgumentParser()

    # required args
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
                        help='The SSH username for the switch.')
    parser.add_argument('--src_port', help='The source layer 4 port of the flow.')
    parser.add_argument('--dest_port', help='The destination layer 4 port of the flow.')
    parser.add_argument('--vrf',
                        help='The VRF of the flow.')
    parser.add_argument('--mode',
                        choices=['interactive', 'auto'],
                        default='interactive')
    parser.add_argument('--use_mgmt', action='store_true')

    args = parser.parse_args()
    while not args.src:
        args.src = raw_input('Enter source IP of the flow: ')
    while not args.dest:
        args.dest = raw_input('Enter destination IP of the flow: ')
    while not args.proto:
        args.proto = raw_input('Enter IP protocol(tcp, udp, icmp, <number>): ')
    while not args.target:
        args.target = raw_input('Enter IP or hostname of first switch to connect to: ')
    while not args.user:
        args.user = raw_input('Enter the SSH username: ')
    if args.use_mgmt is False:
        args.use_mgmt = None
    while args.use_mgmt is None:
        args.use_mgmt = args.use_mgmt or raw_input('Use Management Interfaces for SSH[Y/N]: ')
        if args.use_mgmt.lower().startswith('y'):
            args.use_mgmt = True
        elif args.use_mgmt.lower().startswith('n'):
            args.use_mgmt = False
        else:
            args.use_mgmt = None

    if args.mode == 'interactive':
        args.src_port = args.src_port or raw_input('(Optional) TCP/UDP Source Port: ')
        args.dest_port = args.dest_port or raw_input('(Optional) TCP/UDP Destination Port: ')
        args.vrf = args.vrf or raw_input('(Optional) VRF of the flow: ')

    if bool(args.src_port) != bool(args.dest_port):
        print "--src_port and --dest_port must be supplied together."
        sys.exit()

    args.pwd = getpass("SSH Password: ")
    args.target = socket.gethostbyname(args.target)
    args.src = socket.gethostbyname(args.src)
    args.dest = socket.gethostbyname(args.dest)
    args.proto = convert_proto(args.proto)

    return args

if __name__ == "__main__":
    args = handle_args()

    username = 'cisco'
    password = '!cisco123!'

    intro = intro(args)
    print intro

    connect_ip = args.target
    out_if = 'unknown'
    hop_number = 1
    while args.target != args.dest\
            and 'local' not in out_if:
        try:
            device = ConnectHandler(
                device_type='cisco_nxos',
                ip=connect_ip,
                username=args.user,
                password=args.pwd,
                verbose=False
            )
        except:
            print 'Error SSHing to device at {}'.format(
                connect_ip)
            print 'This may not be a Cisco device, or there may an authentication issue.'
            sys.exit()

        # get stats from switch
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

        out_if = hash_info.get('out_if')
        iface_stats = get_iface_stats(device, out_if)
        hostname = get_hostname(device)

        hash_info.update(iface_stats)

        out = stringify(args.target, args.dest, hostname, hop_number, **hash_info)
        print out

        args.target = hash_info.get('next_hop')
        out_if = hash_info.get('out_if')

        if args.use_mgmt:
            connect_ip = get_mgmt(device, args.target)
        else:
            connect_ip = args.target

        device.disconnect()
        hop_number += 1

        if args.mode == 'interactive':
            loop = 'a'
            while loop:
                loop = raw_input("Hit Enter to Continue...")
