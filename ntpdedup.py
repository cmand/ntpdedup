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

@functools.total_ordering
class NTPServer(object):
    def __init__(self, address):
        self.address = address
        self.version = 0
        self.stratum = 0
        self.precision = 0
        self.ref_id = 0
        self.ref_ts = 0
        self.response_time = 0.0

    def __eq__(self, other):
        return self.version == other.version and \
                self.stratum == other.stratum and \
                self.precision == other.precision and \
                self.ref_id == other.ref_id and \
                self.ref_ts == other.ref_ts

    def __lt__(self, other):
        if self.version != other.version:
            return self.version < other.version
        if self.stratum != other.stratum:
            return self.stratum < other.stratum
        if self.precision != other.precision:
            return self.precision < other.precision
        if self.ref_id != other.ref_id:
            return self.ref_id < other.ref_id
        if self.ref_ts != other.ref_ts:
            return self.ref_ts < other.ref_ts
        return False

    def __str__(self):
        return "NTP server {0} version={1} stratum={2} precision={3} refid={4:08X} refts={5:016X} resp={6:.6f}".format(self.address, self.version, self.stratum, self.precision, self.ref_id, self.ref_ts, self.response_time)

    def get_address(self):
        return self.address

    def get_request(self):
        addrinfo = socket.getaddrinfo(self.address, 123, 0, 0, 0, socket.AI_NUMERICHOST)[0]
        rand = os.urandom(8)
        self.tx_ts = struct.unpack("!Q", rand)[0]
        packet = bytes([0xe3] + 39 * [0x00]) + rand

        self.has_response = False

        return addrinfo[0], addrinfo[4], packet

    def process_response(self, packet):
        if len(packet) < 48:
            return False

        (lvm, stratum, poll, precision, delay, disp, ref_id, ref_ts, orig_ts, rx_ts, tx_ts) = struct.unpack('!BBbbIIIQQQQ', packet[0:48])

        if orig_ts != self.tx_ts or lvm >> 6 == 3 or stratum == 0:
            return False

        self.version = (lvm >> 3) & 0x7
        self.stratum = stratum
        self.precision = precision
        self.ref_id = ref_id
        self.ref_ts = ref_ts
        self.response_time = float(tx_ts - rx_ts) / 2**32

        self.has_response = True
        return True

    def responded(self):
        return self.has_response

def update_servers(servers):
    ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ipv4_socket.settimeout(0.0)
    ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    ipv6_socket.settimeout(0.0)

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
                    packet, sockaddr = s.recvfrom(48)
                    again = True
                    if sockaddr in sockaddr_map:
                        if sockaddr_map[sockaddr].process_response(packet):
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

def print_duplicates(duplicates):
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
            print(*sorted(group), sep=' ')

def main():
    parser = optparse.OptionParser(usage="Usage: %prog [OPTION]... ADDRESS...")
    parser.add_option("-i", "--iterations", dest="iterations", type="int", default=1, help="specify number of iterations (default 1)")
    parser.add_option("-w", "--wait", dest="wait", type="float", default=100.0, help="specify interval between iterations (default 100)")
    parser.add_option("-v", "--verbose", action="count", dest="verbose", default=0, help="increase verbosity")

    (options, addresses) = parser.parse_args()

    servers = []
    duplicates = dict()

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

if __name__ == "__main__":
    main()
