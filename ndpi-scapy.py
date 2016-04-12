#!/usr/bin/env python
"""
nDPI fuzzy testing using scapy
"""
import argparse
import time
import datetime
import subprocess
import random
import re
import os
import sys
from contextlib import contextmanager

import scapy
import scapy.layers.inet
from scapy.route import Route


@contextmanager
def stdout_redirected(new_stdout):
    """ Helper class to redirect stdout """
    save_stdout = sys.stdout
    sys.stdout = new_stdout
    try:
        yield None
    finally:
        sys.stdout = save_stdout


class NdpiScapy(object):
    """ Scapy-powered script for sending malformed packets to ndpiReadr """

    STARTUP_DELAY = 4
    SEND_DELAY = 0.01

    def __init__(self, flags):
        self.flags = flags
        self.dev_null = open(os.devnull, 'w')
        self.proc = None
        self.report_index = self.available_report_index()

    def available_report_index(self):
        """ Find next available index for report """
        matches = [re.match(r"^run\-(\d+)\-.*\.log", s)
                   for s in os.listdir(self.flags.out)]
        indices = [int(m.group(1)) for m in matches if m]
        if len(indices) > 0:
            return indices[-1] + 1
        else:
            return 0

    def get_filename(self, suffix):
        """ Make a log filename """
        return "{}/run-{}-{}".format(self.flags.out, self.report_index, suffix)

    def start_ndpi(self):
        """ Launch ndpiReader """
        self.proc = subprocess.Popen(
            [self.flags.binary, "-i", self.flags.iface],
            stdout=self.dev_null,
            stderr=subprocess.PIPE)
        time.sleep(self.STARTUP_DELAY)

    def stop_ndpi(self):
        """ Stop child or orphaned processes """
        if self.proc and self.proc.poll() == None:
            self.proc.terminate()
        subprocess.Popen(["killall", "-9", "-q", "ndpiReader"])

    def generate(self):
        """ Craft TCP or UDP packets """
        body = scapy.packet.Raw(
            scapy.volatile.RandBin(scapy.volatile.RandNum(\
                self.flags.min_payload, self.flags.max_payload)))
        while True:
            packet = scapy.layers.inet.IP(dst=self.flags.target, frag=0)
            # tcp packets should be more often
            is_tcp = random.random() < 0.8
            if is_tcp:
                packet = packet / scapy.packet.fuzz(
                    scapy.layers.inet.TCP(
                        dataofs=5,
                        reserved=0,
                        flags="SPAE",
                        window=65535,
                        urgptr=0,
                        options=[]) / body)
                if packet[scapy.layers.inet.TCP].dport != 22:
                    return packet
            else:
                packet = packet / scapy.packet.fuzz(
                    scapy.layers.inet.UDP() / body)
                if packet[scapy.layers.inet.UDP].dport != 22:
                    return packet

    def main_loop(self):
        """ Main loop """

        packet_num = 0
        fail_num = 0

        # The loop
        while not self.flags.max_packets or packet_num < self.flags.max_packets:

            # need restart?
            if self.flags.restart and self.flags.restart * packet_num > 0 and \
                  divmod(packet_num, self.flags.restart)[1] == 0:
                self.stop_ndpi()
                self.start_ndpi()

            if self.flags.stats * packet_num > 0 and \
                  divmod(packet_num, self.flags.stats)[1] == 0:
                print "\n[-] packets:", packet_num, "errors:", fail_num

            # Generate and send one packet
            packet = self.generate()
            scapy.sendrecv.send(packet, iface=self.flags.iface)
            time.sleep(self.SEND_DELAY)

            packet_num += 1

            # Check process health
            if self.proc.poll() == None:
                sys.stdout.write('.')
                sys.stdout.flush()
            else:
                sys.stdout.write('x')
                sys.stdout.flush()
                fail_num += 1
                self.report(packet)
                # Restart process
                self.start_ndpi()

        print "\n[+] total packets:", packet_num, "errors:", fail_num

    def process(self):
        """ Entry point """
        print "[+] starting"
        print "[+] saving logs to: " + self.flags.out
        print "[+] found logs: " + str(self.report_index)

        self.stop_ndpi()

        # Silent mode
        scapy.config.conf.verb = False

        try:
            # Start first process
            self.start_ndpi()

            # Run loop
            self.main_loop()
        finally:
            print "[+] done"
            # Kill reader process if it was alive
            self.stop_ndpi()

    def report(self, packet):
        """ Save packet, pcap and stderr to the next log tuple """
        errors = self.proc.stderr.read()
        with open(self.get_filename("error.log"), 'w') as logf:
            logf.write(errors)

        with open(self.get_filename("packet.log"), 'w') as logf:
            with stdout_redirected(logf):
                print "Failed at ", str(datetime.datetime.now())
                packet.show2()
                scapy.utils.hexdump(packet)

        scapy.utils.wrpcap(self.get_filename("dump.pcap"), packet)

        self.report_index += 1


def parse_args():
    """ Parse command line """
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', '-t', required=True,
                        help='target host ip')
    parser.add_argument('--iface', '-i', required=True,
                        help='network interface')
    parser.add_argument('--binary', '-b', required=True,
                        help='path to ndpiReader binary')
    parser.add_argument('--out', '-o', required=True,
                        help='output directory')
    parser.add_argument('--max-packets', '-m', type=int,
                        help='max packets to send (default: infinite)')
    parser.add_argument('--restart', '-r', type=int,
                        help='restart ndpiReader each NUM packets')
    parser.add_argument('--stats', '-s', default=100, type=int,
                        help='show stats each NUM packets (default: %(default)s)')
    parser.add_argument('--min-payload', default=1, type=int,
                        help='minimum payload size (default: %(default)s)')
    parser.add_argument('--max-payload', default=100, type=int,
                        help='minimum payload size (default: %(default)s)')
    return parser.parse_args()

if __name__ == "__main__":
    NdpiScapy(parse_args()).process()

# vim: et ts=4 sw=4
