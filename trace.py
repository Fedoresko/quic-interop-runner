import logging
from enum import Enum
from typing import Optional, Callable

import pyshark

from result import FailedTestException, PassedTestException

IP4_CLIENT = "193.167.0.100"
IP4_SERVER = "193.167.100.100"
IP6_CLIENT = "fd00:cafe:cafe:0::100"
IP6_SERVER = "fd00:cafe:cafe:100::100"


QUIC_V2 = hex(0x6B3343CF)


class Direction(Enum):
    ALL = 0
    FROM_CLIENT = 1
    FROM_SERVER = 2
    INVALID = 3


class PacketType(Enum):
    INITIAL = 1
    HANDSHAKE = 2
    ZERORTT = 3
    RETRY = 4
    ONERTT = 5
    VERSIONNEGOTIATION = 6
    INVALID = 7


WIRESHARK_PACKET_TYPES = {
    PacketType.INITIAL: "0",
    PacketType.ZERORTT: "1",
    PacketType.HANDSHAKE: "2",
    PacketType.RETRY: "3",
}


WIRESHARK_PACKET_TYPES_V2 = {
    PacketType.INITIAL: "1",
    PacketType.ZERORTT: "2",
    PacketType.HANDSHAKE: "3",
    PacketType.RETRY: "0",
}


def get_direction(p) -> Direction:
    if (hasattr(p, "ip") and p.ip.src == IP4_CLIENT) or (
        hasattr(p, "ipv6") and p.ipv6.src == IP6_CLIENT
    ):
        return Direction.FROM_CLIENT

    if (hasattr(p, "ip") and p.ip.src == IP4_SERVER) or (
        hasattr(p, "ipv6") and p.ipv6.src == IP6_SERVER
    ):
        return Direction.FROM_SERVER

    return Direction.INVALID


def get_packet_type(p) -> PacketType:
    if p.quic.header_form == "0":
        return PacketType.ONERTT
    if p.quic.version == "0x00000000":
        return PacketType.VERSIONNEGOTIATION
    if p.quic.version == QUIC_V2:
        for t, num in WIRESHARK_PACKET_TYPES_V2.items():
            if p.quic.long_packet_type_v2 == num:
                return t
        return PacketType.INVALID
    for t, num in WIRESHARK_PACKET_TYPES.items():
        if p.quic.long_packet_type == num:
            return t
    return PacketType.INVALID

class LongHeaderFilter:
    _func: Callable
    packet_type: PacketType

    def __init__(self, packet_type: PacketType, func: Callable):
        self._func = func
        self.packet_type = packet_type

    def filter(self, p):
        for layer in p.layers:
            if layer.layer_name == "quic" and (
                    (
                            hasattr(layer, "long_packet_type")
                            and layer.long_packet_type
                            == WIRESHARK_PACKET_TYPES[self.packet_type]
                    )
                    or (
                            hasattr(layer, "long_packet_type_v2")
                            and layer.long_packet_type_v2
                            == WIRESHARK_PACKET_TYPES_V2[self.packet_type]
                    )
            ):
                self._func(layer)



class OneRttFilter:
    _func: Callable

    def __init__(self, func: Callable):
            self._func = func

    def filter(self, p):
        for layer in p.layers:
            if (
                    layer.layer_name == "quic"
                    and not hasattr(layer, "long_packet_type")
                    and not hasattr(layer, "long_packet_type_v2")
            ): self._func(layer);



class TraceAnalyzer:
    _filename = ""

    def __init__(self, filename: str, keylog_file: Optional[str] = None):
        self._filename = filename
        self._keylog_file = keylog_file

    def _get_direction_filter(self, d: Direction) -> str:
        f = "(quic && !icmp) && "
        if d == Direction.FROM_CLIENT:
            return (
                f + "(ip.src==" + IP4_CLIENT + " || ipv6.src==" + IP6_CLIENT + ") && "
            )
        elif d == Direction.FROM_SERVER:
            return (
                f + "(ip.src==" + IP4_SERVER + " || ipv6.src==" + IP6_SERVER + ") && "
            )
        else:
            return f

    def _for_each_packet(self, filter_str: str, fun : Callable) -> None:
        override_prefs = {}
        if self._keylog_file is not None:
            override_prefs["tls.keylog_file"] = self._keylog_file
        cap = pyshark.FileCapture(
            self._filename,
            display_filter=filter_str,
            keep_packets = False,
            override_prefs=override_prefs,
            disable_protocol="http3",  # see https://github.com/quic-interop/quic-interop-runner/pull/179
            decode_as={"udp.port==443": "quic"},
        )
        # If the pcap has been cut short in the middle of the packet, pyshark will crash.
        # See https://github.com/KimiNewt/pyshark/issues/390.
        # -- or in case of OOM due to storing all PCAP as XML
        
        has_non_decrypted = False
        try:
            for p in cap:
                if hasattr(p["quic"], "decryption_failed"):
                    has_non_decrypted = True
                else: fun(p)
        except (FailedTestException, PassedTestException):
            raise
        except Exception as e:
            logging.debug(e)
        finally:
            cap.close()
        
        if has_non_decrypted:
            logging.info("At least one QUIC packet could not be decrypted")


    def for_each_raw_packet(self, fun: Callable, direction: Direction = Direction.ALL):
        self._for_each_packet(fun, self._get_direction_filter(direction) + "quic")


    def for_each_1rtt(self, fun: Callable, direction: Direction = Direction.ALL):
        """Get all QUIC packets, one or both directions."""
        one_rtt_filter = OneRttFilter(fun)

        self._for_each_packet(
            self._get_direction_filter(direction) + "quic.header_form==0",
            one_rtt_filter.filter
        )

    def for_each_version_negotiation_packet(self, fun : Callable, direction: Direction = Direction.ALL):
        self._for_each_packet(
            self._get_direction_filter(direction) + "quic.version==0",
            fun
        )

    def _for_each_long_header_packet(
        self, packet_type: PacketType, fun: Callable, direction: Direction
    ):
        lh_filter = LongHeaderFilter(packet_type, fun)
        self._for_each_packet(
            self._get_direction_filter(direction)
            + "(quic.long.packet_type || quic.long.packet_type_v2)",
            lh_filter.filter
        )

    def for_each_initial(self, fun : Callable, direction: Direction = Direction.ALL):
        """Each Initial packet."""
        self._for_each_long_header_packet(PacketType.INITIAL, fun, direction)

    def for_each_retry(self, fun : Callable, direction: Direction = Direction.ALL):
        """Each Retry packet."""
        self._for_each_long_header_packet(PacketType.RETRY, fun, direction)

    def for_each_handshake(self, fun : Callable, direction: Direction = Direction.ALL):
        """Each Handshake packet."""
        self._for_each_long_header_packet(PacketType.HANDSHAKE, fun, direction)

    def for_each_0rtt(self, fun : Callable):
        """Each 0-RTT packet."""
        self._for_each_long_header_packet(PacketType.ZERORTT, fun, Direction.FROM_CLIENT)
