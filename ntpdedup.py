#!/usr/bin/python3
#
# Tool for detecting duplicated NTP servers
#
# Copyright (C) 2017  Miroslav Lichvar <mlichvar0@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import functools
import optparse
import os
import socket
import struct
import sys
import time
import ipaddress

@functools.total_ordering
class NTPServer(object):
    def __init__(self, address):
        self.address = address
        self.version = 0
        self.stratum = 0
        self.poll = 0
        self.precision = 0
        self.root_delay = 0.0
        self.root_dispersion = 0.0
        self.ref_id = 0
        self.ref_ts = 0
        self.response_time = 0.0
        self.dscp = 0
        self.hlim = 0

    def __eq__(self, other):
        return self.version == other.version and \
                self.stratum == other.stratum and \
                self.poll == other.poll and \
                self.precision == other.precision and \
                self.ref_id == other.ref_id and \
                self.ref_ts == other.ref_ts

    def __lt__(self, other):
        if self.version != other.version:
            return self.version < other.version
        if self.stratum != other.stratum:
            return self.stratum < other.stratum
        if self.poll != other.poll:
            return self.poll < other.poll
        if self.precision != other.precision:
            return self.precision < other.precision
        if self.ref_id != other.ref_id:
            return self.ref_id < other.ref_id
        if self.ref_ts != other.ref_ts:
            return self.ref_ts < other.ref_ts
        return False

    def __str__(self):
        return "NTP server {0} version={1} stratum={2} poll={3} precision={4} rdelay={5:.6f} rdisp={6:.6f} refid={7:08X}({8}) refts={9:016X} resp={10:.6f} dscp={11} hlim={12}".format(self.address, self.version, self.stratum, self.poll, self.precision, self.root_delay, self.root_dispersion, self.ref_id, refid_to_str(self.ref_id), self.ref_ts, self.response_time, self.dscp, self.hlim)

    def get_address(self):
        return self.address

    def get_request(self):
        addrinfo = socket.getaddrinfo(self.address, 123, 0, 0, 0, socket.AI_NUMERICHOST)[0]
        rand = os.urandom(8)
        self.tx_ts = struct.unpack("!Q", rand)[0]
        packet = bytes([0xe3] + 39 * [0x00]) + rand

        self.has_response = False

        return addrinfo[0], addrinfo[4], packet

    def process_response(self, packet, hlim, dscp):
        if len(packet) < 48:
            return False

        (lvm, stratum, poll, precision, delay, disp, ref_id, ref_ts, orig_ts, rx_ts, tx_ts) = struct.unpack('!BBbbIIIQQQQ', packet[0:48])

        if orig_ts != self.tx_ts or lvm >> 6 == 3 or stratum == 0:
            return False

        self.version = (lvm >> 3) & 0x7
        self.stratum = stratum
        self.poll = poll
        self.precision = precision
        self.root_delay = ntp_short_to_float(delay)
        self.root_dispersion = ntp_short_to_float(disp)
        self.ref_id = ref_id
        self.ref_ts = ref_ts
        self.response_time = float(tx_ts - rx_ts) / 2**32
        self.dscp = dscp  
        self.hlim = hlim

        self.has_response = True
        return True

    def responded(self):
        return self.has_response

# The 32-bit NTP short format used in delay and dispersion calculations is seconds 
# and fraction with the decimal point to the left of bit 16.
def ntp_short_to_float(x):
    sec  = x >> 16
    frac = (x & 0x0000ffff)
    frac = frac / 65536.0
    return (frac + sec)

""" convert an NTP stratum 1 refid to a string """
def refid_to_str(n):
    s = struct.pack('!I', n)
    return s.decode("ascii", errors="ignore")

def update_servers(servers):
    ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ipv4_socket.settimeout(0.0)
    try:
        ipv4_socket.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)
        ipv4_socket.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    except OSError:
        pass
    ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    ipv6_socket.settimeout(0.0)
    ipv6_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
    ipv6_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)

    updated = 0
    sockaddr_map = dict()

    for server in servers + 20 * [None]:
        if server is not None:
            family, sockaddr, packet = server.get_request()
            sockaddr_map[sockaddr] = server
            try:
                if family == socket.AF_INET:
                    ipv4_socket.sendto(packet, sockaddr)
                elif family == socket.AF_INET6:
                    ipv6_socket.sendto(packet, sockaddr)
            except socket.error:
                pass

        time.sleep(0.01)

        while True:
            again = False
            for s in [ipv4_socket, ipv6_socket]:
                try:
                    packet, ancdata, msg_flags, sockaddr = s.recvmsg(1024, socket.CMSG_LEN(32))
                    again = True
                    hlim = 0
                    dscp = 0
                    for cmsg_level, cmsg_type, cmsg_data in ancdata:
                        if cmsg_level == socket.IPPROTO_IP:
                            if cmsg_type == socket.IP_TTL:
                                hlim = struct.unpack("i", cmsg_data)[0]
                            elif cmsg_type == socket.IP_TOS:
                                tclass = struct.unpack("b", cmsg_data)[0]
                                dscp = (tclass & 0xfc) >> 2 # 6MSB of tclass
                        elif cmsg_level == socket.IPPROTO_IPV6:
                            if cmsg_type == socket.IPV6_HOPLIMIT:
                                hlim = struct.unpack("i", cmsg_data)[0]
                            elif cmsg_type == socket.IPV6_TCLASS:
                                tclass = struct.unpack("i", cmsg_data)[0]
                                dscp = (tclass & 0xfc) >> 2 # 6MSB of tclass

                    if sockaddr in sockaddr_map:
                        if sockaddr_map[sockaddr].process_response(packet,hlim,dscp):
                            updated += 1
                except socket.error:
                    packet = b""

            if not again:
                break

    ipv4_socket.close()
    ipv6_socket.close()

    return updated

def update_duplicates(duplicates, servers):
    for i in range(len(servers)):
        if not servers[i].responded():
            continue
        for j in range(i + 1, len(servers)):
            if not servers[j].responded():
                continue
            if servers[i] != servers[j]:
                break;
            addresses = tuple(sorted([servers[i].get_address(), servers[j].get_address()]))
            if addresses not in duplicates:
                duplicates[addresses] = 0
            duplicates[addresses] += 1

def print_duplicates(duplicates, output=sys.stdout, sep=' '):
    groups = dict()

    all_addresses = set()
    for addresses in duplicates.keys():
        all_addresses |= set(addresses)

    done = set()
    for address in all_addresses:
        if address in done:
            continue
        group = set([address])
        for (addresses, count) in duplicates.items():
            if count < 1:
                continue
            set_addresses = set(addresses)
            if address not in set_addresses:
                continue
            group |= set_addresses
            done |= set_addresses
        if len(group):
            print(*sorted(group), file=output, sep=sep)

def print_duplicate_statistics(duplicates, servers):
    all_ipv4 = set()
    all_ipv6 = set()
    dups_ipv4_ipv4 = set()
    dups_ipv6_ipv4 = set()
    dups_ipv4_ipv6 = set()
    dups_ipv6_ipv6 = set()
    unique = set()

    for server in servers:
        address = server.get_address()
        if '.' in address:
            all_ipv4.add(address)
        else:
            all_ipv6.add(address)
        unique.add(address)

    for (addresses, count) in duplicates.items():
        if count < 1:
            continue
        if '.' in addresses[0]:
            if '.' in addresses[1]:
                dups_ipv4_ipv4 |= set(addresses)
            else:
                dups_ipv4_ipv6.add(addresses[0])
                dups_ipv6_ipv4.add(addresses[1])
        else:
            if '.' in addresses[1]:
                dups_ipv4_ipv6.add(addresses[1])
                dups_ipv6_ipv4.add(addresses[0])
            else:
                dups_ipv6_ipv6 |= set(addresses)
        unique -= set(sorted(addresses)[1:])

    print("  IPv4 servers             {0:4}".format(len(all_ipv4)))
    if len(all_ipv4):
        print("    with IPv4 duplicates   {0:4} ({1:.1f}%)".format(len(dups_ipv4_ipv4), 100.0 * len(dups_ipv4_ipv4) / len(all_ipv4)))
        print("    with IPv6 duplicates   {0:4} ({1:.1f}%)".format(len(dups_ipv4_ipv6), 100.0 * len(dups_ipv4_ipv6) / len(all_ipv4)))
    print("  IPv6 servers             {0:4}".format(len(all_ipv6)))
    if len(all_ipv6):
        print("    with IPv4 duplicates   {0:4} ({1:.1f}%)".format(len(dups_ipv6_ipv4), 100.0 * len(dups_ipv6_ipv4) / len(all_ipv6)))
        print("    with IPv6 duplicates   {0:4} ({1:.1f}%)".format(len(dups_ipv6_ipv6), 100.0 * len(dups_ipv6_ipv6) / len(all_ipv6)))
    print("  Unique servers           {0:4}".format(len(unique)))

def main():
    parser = optparse.OptionParser(usage="Usage: %prog [OPTION]... ADDRESS...")
    parser.add_option("-i", "--iterations", dest="iterations", type="int", default=1, help="specify number of iterations (default 1)")
    parser.add_option("-w", "--wait", dest="wait", type="float", default=100.0, help="specify interval between iterations (default 100)")
    parser.add_option("-o", "--output", help="duplicate output csv")
    parser.add_option("-t", "--targets", help="input targets")
    parser.add_option("-v", "--verbose", action="count", dest="verbose", default=0, help="increase verbosity")

    (options, addresses) = parser.parse_args()

    servers = []
    duplicates = dict()

    if options.targets:
        with open(options.targets, 'r') as f:
            for line in f:
                if (line[0] == '#') or (len(line) <= 4):
                    continue
                address = line.strip()
                try:
                    ipaddress.ip_address(address)
                    servers.append(NTPServer(address))
                except:
                    print("invalid address: %s" % address)

    for address in addresses:
        servers.append(NTPServer(address))

    for i in range(options.iterations):
        updated = update_servers(servers[::2])
        time.sleep(1.0)
        updated += update_servers(servers[1::2])

        servers.sort()
        update_duplicates(duplicates, servers)

        if options.verbose:
            print("Iteration {0}: responded {1}/{2} servers".format(i + 1, updated, len(servers)))
            if options.verbose > 1:
                for server in servers:
                    if server.responded():
                        print(server)

        if i + 1 < options.iterations:
            time.sleep(options.wait)

    if options.verbose:
        print("Duplicates:")

    print_duplicates(duplicates)

    if options.output:
        with open(options.output, 'w') as f:
            print_duplicates(duplicates, output=f, sep=',')

    if options.verbose:
        print("Statistics:")
        print_duplicate_statistics(duplicates, servers)

if __name__ == "__main__":
    if not hasattr(socket,'IP_RECVTTL'):
        socket.IP_RECVTTL = 12
    main()
