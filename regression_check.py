#!/usr/bin/env python3
"""Regression check against the DHCP SERVER 2.52 reference capture (DHCP.pcapng).

Feed the captured client Discover/Request into our build_reply() and compare the
resulting Offer/ACK, field by field, with the real replies in the capture.

Usage:
    python regression_check.py
"""
import os
import sys

from scapy.all import rdpcap
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dhcp_server import BROADCAST_IP, BROADCAST_MAC, build_reply  # noqa: E402

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DHCP.pcapng")

# Values taken from the reference capture (frame 6 Offer / frame 8 ACK)
REF_SERVER_IP = "192.168.1.1"
REF_SERVER_MAC = "34:29:8f:73:62:ad"
REF_OFFERED_IP = "192.168.1.20"

MTYPES = {1: "discover", 2: "offer", 3: "request", 5: "ack"}


def msg_type(pkt):
    if DHCP not in pkt:
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return opt[1]
    return None


def clean_options(pkt):
    """DHCP options without padding; message-type normalized to a number because
    Scapy decodes wire values as ints while build_reply writes symbolic names."""
    if DHCP not in pkt:
        return []
    out = []
    aliases = {"discover": 1, "offer": 2, "request": 3, "ack": 5}
    for o in pkt[DHCP].options:
        if o in ("pad", "end"):
            continue
        if isinstance(o, tuple) and o[0] == "message-type":
            o = ("message-type", aliases.get(o[1], o[1]))
        out.append(o)
    return out


def field_pairs(ours, ref):
    """Yield (label, our_value, ref_value) for every protocol field we compare."""
    for layer, name in ((Ether, "src"), (Ether, "dst"),
                        (IP, "src"), (IP, "dst"),
                        (UDP, "sport"), (UDP, "dport")):
        yield (f"{layer.__name__}.{name}",
               getattr(ours[layer], name), getattr(ref[layer], name))

    b1, b2 = ours[BOOTP], ref[BOOTP]
    for name in ("op", "htype", "hlen", "hops", "xid", "secs", "flags",
                 "ciaddr", "yiaddr", "siaddr", "giaddr"):
        yield (f"BOOTP.{name}", getattr(b1, name), getattr(b2, name))
    yield ("BOOTP.chaddr[0:6]", bytes(b1.chaddr)[:6], bytes(b2.chaddr)[:6])

    yield ("DHCP.options", clean_options(ours), clean_options(ref))


def compare(label, ours, ref):
    print(f"\n=== {label} ===")
    ok_all = True
    for field, a, b in field_pairs(ours, ref):
        ok = a == b
        ok_all = ok_all and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {field:24s} ours={a!s:38s} ref={b}")
    return ok_all


def find_type(pkts, t):
    return [p for p in pkts if msg_type(p) == t]


def check_flag_branches(discover):
    """RFC 2131: broadcast flag set -> broadcast reply, cleared -> unicast."""
    client_mac = bytes(discover[BOOTP].chaddr)[:6].hex(":")
    ok_all = True

    # The captured client sets 0x8000, so the reference path is broadcast.
    broadcast = build_reply(discover, "offer", REF_SERVER_IP,
                            REF_SERVER_MAC, REF_OFFERED_IP)
    expected = [(Ether, "dst", BROADCAST_MAC), (IP, "dst", BROADCAST_IP)]
    print("\n=== RFC broadcast-flag: 0x8000 (broadcast) ===")
    for layer, name, want in expected:
        got = getattr(broadcast[layer], name)
        ok = got == want
        ok_all = ok_all and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {layer.__name__}.{name:4s} got={got} want={want}")

    # Clear the flag: reply must be unicast to chaddr / yiaddr.
    unicast_request = discover.copy()
    unicast_request[BOOTP].flags = 0
    unicast = build_reply(unicast_request, "offer", REF_SERVER_IP,
                          REF_SERVER_MAC, REF_OFFERED_IP)
    expected = [(Ether, "dst", client_mac), (IP, "dst", REF_OFFERED_IP),
                (BOOTP, "flags", 0)]
    print("\n=== RFC broadcast-flag: 0x0000 (unicast) ===")
    for layer, name, want in expected:
        got = getattr(unicast[layer], name)
        ok = got == want
        ok_all = ok_all and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {layer.__name__}.{name:4s} "
              f"got={got if name != 'flags' else int(got)} want={want}")
    return ok_all


def main():
    if not os.path.exists(PCAP):
        print("找不到抓包文件:", PCAP)
        return 1
    pkts = rdpcap(PCAP)
    discovers = find_type(pkts, 1)
    requests = find_type(pkts, 3)
    offers = find_type(pkts, 2)
    acks = find_type(pkts, 5)
    if not (discovers and requests and offers and acks):
        print("抓包缺少 DORA 报文，无法回归")
        return 1

    discover, request = discovers[-1], requests[-1]   # 最后一次成功交互
    ref_offer, ref_ack = offers[-1], acks[-1]

    our_offer = build_reply(discover, "offer", REF_SERVER_IP,
                            REF_SERVER_MAC, REF_OFFERED_IP)
    our_ack = build_reply(request, "ack", REF_SERVER_IP,
                          REF_SERVER_MAC, REF_OFFERED_IP)

    ok1 = compare("Offer: our build_reply vs reference #6", our_offer, ref_offer)
    ok2 = compare("ACK:   our build_reply vs reference #8", our_ack, ref_ack)
    ok3 = check_flag_branches(discover)

    print("\n=== summary ===")
    print(f"  Offer: {'PASS' if ok1 else 'FAIL'} | ACK: {'PASS' if ok2 else 'FAIL'} "
          f"| 广播标志分支: {'PASS' if ok3 else 'FAIL'}")
    print(f"  参考报文: {len(pkts)} 帧 | Discover×{len(discovers)} "
          f"Offer×{len(offers)} Request×{len(requests)} ACK×{len(acks)}")
    return 0 if (ok1 and ok2 and ok3) else 1


if __name__ == "__main__":
    sys.exit(main())
