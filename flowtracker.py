import argparse
import socket
import sys
import re
from netmiko import ConnectHandler


def convert_proto(proto):
    """Convert a common protocol name to a protocol number.
    """
    convert_dict = {'icmp': '1',
                    'tcp': '6',
                    'udp': '17'}

    return convert_dict.get(proto, proto)


#def _get_raw_hash_info(**kwargs):
#    # will change to use netmiko
#    filename = kwargs.get('filename') or 'sample_l3_1.txt'
#    with open(filename, "rb") as f:
#        raw = f.read()
#
#    return raw

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
        cmd_str += ' {}'.format(source)

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


def stringify(switch_ip, dest, **hash_info):
    """Pretty print flow information.
    """

    return """
#############################################################################

NODE: {}

LOAD_SHARE_MODE: {}
VRF: {}
OUT_IF: {}
DEST: {}
NEXT_HOP: {}

OUT_IF:
  RESETS: {}
  TX_STATS: {}

""".format(switch_ip,
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
    parser.add_argument('-src',
                        required=True,
                        help='The source IP address or hostname of the flow.')
    parser.add_argument('-dest',
                        required=True,
                        help='The destination IP address or hostname of the flow.')
    parser.add_argument('-proto',
                        required=True,
                        help='The IP protocol number.' +\
                        ' Common names like icmp, tcp, and udp may be used.')
    parser.add_argument('-target',
                        required=True,
                        help='The IP address or hostname of the switch to start the flow track.')
#
#
#    # optional args
#    parser.add_argument('--cred',
#                        help='A credentials file storing the SSH username and password.')
#    parser.add_argument('--user', '-u',
#                        help='The SSH username for the switch.')
#    parser.add_argument('--pwd', '-p',
#                        help='The SSH password for the switch.')
    parser.add_argument('--src_port', '-s', help='The source layer 4 port of the flow.')
    parser.add_argument('--dest_port', '-d', help='The destination layer 4 port of the flow.')
    parser.add_argument('--vrf', '-v',
                        help='The VRF of the flow.')
    parser.add_argument('--mode', '-m',
                        choices=['interactive', 'auto'],
                        default='interactive')
    parser.add_argument('--use_mgmt', action='store_true')

#    # parse and normalize argument
    args = parser.parse_args()
    args.target = socket.gethostbyname(args.target)
    args.src = socket.gethostbyname(args.src)
    args.dest = socket.gethostbyname(args.dest)
    args.proto = convert_proto(args.proto)

    #TODO: assert that source and dest port are given together

    return args


if __name__ == "__main__":
    args = handle_args()

    username = 'cisco'
    password = '!cisco123!'

    intro = intro(args)
    print intro

    
    connect_ip = args.target
    out_if = 'unknown'
    while args.target != args.dest\
            and 'local' not in out_if:
        try:
            device = ConnectHandler(
                device_type='cisco_nxos',
                ip=connect_ip,
                username=username,
                password=password,
                verbose=True
            )
        except:
            print 'Error SSHing to device at {}'.format(
                connect_ip)
            print 'This may not be a Cisco device, or there may an authentication issue.'
            sys.exit()

        #TODO: if not cisco device?

        # get stats from switch
        hash_info = get_hash_info(device, src=args.src, dest=args.dest, ip_proto='1')
        out_if = hash_info.get('out_if')
        iface_stats = get_iface_stats(device, out_if)

        # display to user
        hash_info.update(iface_stats)
        out = stringify(args.target, args.dest, **hash_info)
        print out

        args.target = hash_info.get('next_hop')
        out_if = hash_info.get('out_if')

        if args.use_mgmt:
            connect_ip = get_mgmt(device, args.target)

            #used only for our testing
            temp_map = {
                        '10.1.100.21': '68.170.147.165',
                        '10.1.100.20': '68.170.147.164'
                       }

            connect_ip = temp_map.get(connect_ip, connect_ip)
        else:
            connect_ip = args.target
        
        device.disconnect()

        if args.mode == 'interactive':
            loop = 'a'
            while loop:
                loop = raw_input("Hit Enter to Continue...")







