import logging
import random
import string
import tempfile
from datetime import timedelta
from enum import IntEnum
import random
import string
from trace import (
    QUIC_V2,
    Direction,
    PacketType,
    get_direction,
    get_packet_type,
)
from typing import List, Tuple

from result import TestResult, FailedTestException, PassedTestException
from testcase import (
    QUIC_VERSION,
    Measurement,
    Perspective,
    TestCase,
    generate_cert_chain,
)

KB = 1 << 10
MB = 1 << 20

def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))

class ECN(IntEnum):
    NONE = 0
    ECT1 = 1
    ECT0 = 2
    CE = 3

class TestCaseQuic(TestCase):
    def _check_files(self) -> bool:
        return super()._check_files(
            download_dir=self.client_download_dir(), files=self._files
        )

    def get_paths(self):
        return [self.urlprefix() + p for p in self.get_paths_raw()]

    def get_paths_raw(self):
        return super().get_paths_raw()


class TestCaseVersionNegotiation(TestCaseQuic):
    @staticmethod
    def name():
        return "versionnegotiation"

    @staticmethod
    def abbreviation():
        return "V"

    @staticmethod
    def desc():
        return "A version negotiation packet is elicited and acted on."

    def get_paths_raw(self):
        return [""]

    def check(self) -> TestResult:
        super().check()

        dcid = ""
        def _get_dcid(p):
            nonlocal dcid
            dcid = p.dcid

        def _check_scid(p):
            nonlocal dcid
            if p.scid == dcid:
                raise PassedTestException

        tr = self._client_trace()
        tr.for_each_initial(_get_dcid, Direction.FROM_CLIENT)
        if dcid == "":
            logging.info("Didn't find an Initial / a DCID.")
            return TestResult.FAILED

        try:
            tr.for_each_version_negotiation_packet(_check_scid)
        except PassedTestException:
            return TestResult.SUCCEEDED

        logging.info("Didn't find a Version Negotiation Packet with matching SCID.")
        return TestResult.FAILED


class TestCaseHandshake(TestCaseQuic):
    @staticmethod
    def name():
        return "handshake"

    @staticmethod
    def abbreviation():
        return "H"

    @staticmethod
    def desc():
        return "Handshake completes successfully."

    def get_paths_raw(self):
        self._files = [self._generate_random_file(1 * KB)]
        return self._files

    def check(self) -> TestResult:
        super().check()
        if not self._check_version_and_files():
            return TestResult.FAILED
        if self._retry_sent():
            logging.info("Didn't expect a Retry to be sent.")
            return TestResult.FAILED
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseLongRTT(TestCaseHandshake):
    @staticmethod
    def abbreviation():
        return "LR"

    @staticmethod
    def name():
        return "longrtt"

    @staticmethod
    def testname(p: Perspective):
        return "handshake"

    @staticmethod
    def desc():
        return "Handshake completes when RTT is long."

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "simple-p2p --delay=750ms --bandwidth=10Mbps --queue=25"

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        num_ch = 0
        def _count_client_hellos(p):
            nonlocal num_ch
            if hasattr(p, "tls_handshake_type"):
                if p.tls_handshake_type == "1":
                    num_ch += 1
            # Retransmitted ClientHello does not have
            # tls_handshake_type attribute.  See
            # https://gitlab.com/wireshark/wireshark/-/issues/18696
            # for details.
            elif hasattr(p, "retransmission") or hasattr(p, "overlap"):
                num_ch += 1

        self._client_trace().for_each_initial(_count_client_hellos, Direction.FROM_CLIENT)

        if num_ch < 2:
            logging.info("Expected at least 2 ClientHellos. Got: %d", num_ch)
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseTransfer(TestCaseQuic):
    @staticmethod
    def name():
        return "transfer"

    @staticmethod
    def abbreviation():
        return "DC"

    @staticmethod
    def desc():
        return "Stream data is being sent and received correctly. Connection close completes with a zero error code."

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(2 * MB),
            self._generate_random_file(3 * MB),
            self._generate_random_file(5 * MB),
        ]
        return self._files

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseChaCha20(TestCaseQuic):
    @staticmethod
    def name():
        return "chacha20"

    @staticmethod
    def testname(p: Perspective):
        return "chacha20"

    @staticmethod
    def abbreviation():
        return "C20"

    @staticmethod
    def desc():
        return "Handshake completes using ChaCha20."

    def get_paths_raw(self):
        self._files = [self._generate_random_file(3 * MB)]
        return self._files

    ciphersuites = []

    def _collect_ciphersuits(self, p):
        if hasattr(p, "tls_handshake_ciphersuite"):
            self.ciphersuites.append(p.tls_handshake_ciphersuite)


    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED

        self.ciphersuites = []

        self._client_trace().for_each_initial(self._collect_ciphersuits, Direction.FROM_CLIENT)

        if len(set(self.ciphersuites)) != 1 or (
            self.ciphersuites[0] != "4867" and self.ciphersuites[0] != "0x1303"
        ):
            logging.info(
                "Expected only ChaCha20 cipher suite to be offered. Got: %s",
                set(self.ciphersuites),
            )
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseMultiplexing(TestCaseQuic):
    @staticmethod
    def name():
        return "multiplexing"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def abbreviation():
        return "M"

    @staticmethod
    def desc():
        return "Thousands of files are transferred over a single connection, and server increased stream limits to accomodate client requests."

    def get_paths_raw(self):
        for _ in range(1, 2000):
            self._files.append(self._generate_random_file(32))
        return self._files

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        # Check that the server set a bidirectional stream limit <= 1000
        checked_stream_limit = False

        def _check_params(p):
            nonlocal checked_stream_limit
            if hasattr(p, "tls.quic.parameter.initial_max_streams_bidi"):
                checked_stream_limit = True
                stream_limit = int(
                    getattr(p, "tls.quic.parameter.initial_max_streams_bidi")
                )
                logging.debug("Server set bidirectional stream limit: %d", stream_limit)
                if stream_limit > 1000:
                    logging.info("Server set a stream limit > 1000.")
                    raise FailedTestException

        try:
            self._client_trace().for_each_handshake(_check_params, Direction.FROM_SERVER)
        except FailedTestException:
            return TestResult.FAILED

        if not checked_stream_limit:
            logging.info("Couldn't check stream limit.")
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseRetry(TestCaseQuic):
    @staticmethod
    def name():
        return "retry"

    @staticmethod
    def abbreviation():
        return "S"

    @staticmethod
    def desc():
        return "Server sends a Retry, and a subsequent connection using the Retry token completes successfully."

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(10 * KB),
        ]
        return self._files

    def _check_trace(self) -> bool:
        # check that (at least) one Retry packet was actually sent
        tr = self._client_trace()
        tokens = []

        def _check_retry_token(p):
            if not hasattr(p, "retry_token"):
                logging.info("Retry packet doesn't have a retry_token")
                logging.info(p)
                raise FailedTestException
            tokens.append(p.retry_token.replace(":", ""))

        try:
            tr.for_each_retry(_check_retry_token, Direction.FROM_SERVER)
        except FailedTestException:
            return False

        if len(tokens) == 0:
            logging.info("Didn't find any Retry packets.")
            return False

        # check that an Initial packet uses a token sent in the Retry packet(s)
        highest_pn_before_retry = -1
        def _check_client_response(p):
            nonlocal highest_pn_before_retry
            pn = int(p.packet_number)
            if p.token_length == "0":
                highest_pn_before_retry = max(highest_pn_before_retry, pn)
                return
            if pn <= highest_pn_before_retry:
                logging.debug(
                    "Client reset the packet number. Check failed for PN %d", pn
                )
                raise FailedTestException
            token = p.token.replace(":", "")
            if token in tokens:
                logging.debug("Check of Retry succeeded. Token used: %s", token)
                raise PassedTestException


        try:
            tr.for_each_initial(_check_client_response, Direction.FROM_CLIENT)
        except PassedTestException:
            return True
        except FailedTestException:
            return False

        logging.info("Didn't find any Initial packet using a Retry token.")
        return False

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        if not self._check_trace():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseResumption(TestCaseQuic):
    @staticmethod
    def name():
        return "resumption"

    @staticmethod
    def abbreviation():
        return "R"

    @staticmethod
    def desc():
        return "Connection is established using TLS Session Resumption."

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(5 * KB),
            self._generate_random_file(10 * KB),
        ]
        return self._files

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED
        num_handshakes = self._count_handshakes()
        if num_handshakes != 2:
            logging.info("Expected exactly 2 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED

        cids = []
        def _collect_handshake_cids(p):
            cids.append(p.scid)

        first_handshake_has_cert = False

        def _check_cert(p):
            nonlocal first_handshake_has_cert
            if p.scid == cids[0]:
                if hasattr(p, "tls_handshake_certificates_length"):
                    first_handshake_has_cert = True
            elif p.scid == cids[len(cids) - 1]:  # second handshake
                if hasattr(p, "tls_handshake_certificates_length"):
                    logging.info(
                        "Server sent a Certificate message in the second handshake."
                    )
                    raise FailedTestException
            else:
                logging.info(
                    "Found handshake packet that neither belongs to the first nor the second handshake."
                )
                raise FailedTestException


        self._client_trace().for_each_handshake(_collect_handshake_cids, Direction.FROM_SERVER)
        try:
            self._client_trace().for_each_handshake(_check_cert, Direction.FROM_SERVER)
        except FailedTestException:
            return TestResult.FAILED

        if not first_handshake_has_cert:
            logging.info(
                "Didn't find a Certificate message in the first handshake. That's weird."
            )
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseZeroRTT(TestCaseQuic):
    NUM_FILES = 40
    FILESIZE = 32  # in bytes
    FILENAMELEN = 250

    @staticmethod
    def name():
        return "zerortt"

    @staticmethod
    def abbreviation():
        return "Z"

    @staticmethod
    def desc():
        return "0-RTT data is being sent and acted on."

    def get_paths_raw(self):
        for _ in range(self.NUM_FILES):
            filename = random_string(self.FILENAMELEN)
            self._files.append(self._generate_random_file(self.FILESIZE, filename))
        return self._files


    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 2:
            logging.info("Expected exactly 2 handshakes. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        tr = self._client_trace()

        payload_size = 0
        def _add_payload_size(p):
            nonlocal payload_size
            """Get the sum of the payload sizes of all packets"""
            if hasattr(p, "long_packet_type") or hasattr(p, "long_packet_type_v2"):
                if hasattr(p, "payload"):  # when keys are available
                    payload_size += len(p.payload.split(":"))
                else:
                    payload_size += len(p.remaining_payload.split(":"))
            else:
                if hasattr(p, "protected_payload"):
                    payload_size += len(p.protected_payload.split(":"))

        tr.for_each_0rtt(_add_payload_size)
        zeroRTTSize = payload_size
        payload_size = 0
        tr.for_each_1rtt(_add_payload_size, Direction.FROM_CLIENT)
        oneRTTSize = payload_size

        logging.debug("0-RTT size: %d", zeroRTTSize)
        logging.debug("1-RTT size: %d", oneRTTSize)
        if zeroRTTSize == 0:
            logging.info("Client didn't send any 0-RTT data.")
            return TestResult.FAILED
        if oneRTTSize > 0.5 * self.FILENAMELEN * self.NUM_FILES:
            logging.info("Client sent too much data in 1-RTT packets.")
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseHTTP3(TestCaseQuic):
    @staticmethod
    def name():
        return "http3"

    @staticmethod
    def abbreviation():
        return "3"

    @staticmethod
    def desc():
        return "An H3 transaction succeeded."

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(5 * KB),
            self._generate_random_file(10 * KB),
            self._generate_random_file(500 * KB),
        ]
        return self._files

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseAmplificationLimit(TestCaseQuic):
    @staticmethod
    def name():
        return "amplificationlimit"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def abbreviation():
        return "A"

    @staticmethod
    def desc():
        return "The server obeys the 3x amplification limit."

    def certs_dir(self):
        if not self._cert_dir:
            self._cert_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="certs_")
            generate_cert_chain(self._cert_dir.name, 9)
        return self._cert_dir.name + "/"

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        # Let the ClientHello pass, but drop a bunch of retransmissions afterwards.
        return "droplist --delay=15ms --bandwidth=10Mbps --queue=25 --drops_to_server=2,3,4,5,6,7"

    def get_paths_raw(self):
        self._files = [self._generate_random_file(5 * KB)]
        return self._files

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        # Check the highest offset of CRYPTO frames sent by the server.
        # This way we can make sure that it actually used the provided cert chain.
        max_handshake_offset = 0

        def _get_max_handshake_offset(p):
            nonlocal max_handshake_offset
            if hasattr(p, "crypto_offset"):
                max_handshake_offset = max(
                    max_handshake_offset, int(p.crypto_offset) + int(p.crypto_length)
                )

        self._server_trace().for_each_handshake(_get_max_handshake_offset, Direction.FROM_SERVER)

        if max_handshake_offset < 7500:
            logging.info(
                "Server sent too little Handshake CRYPTO data (%d bytes). Not using the provided cert chain?",
                max_handshake_offset,
            )
            return TestResult.FAILED
        logging.debug(
            "Server sent %d bytes in Handshake CRYPTO frames.", max_handshake_offset
        )

        # Check that the server didn't send more than 3-4x what the client sent.
        allowed = 0
        allowed_with_tolerance = 0
        client_sent, server_sent = 0, 0  # only for debug messages
        log_output = []

        def proc_packet(p):
            nonlocal allowed, allowed_with_tolerance, client_sent, server_sent
            direction = get_direction(p)
            packet_type = get_packet_type(p)

            if packet_type == PacketType.VERSIONNEGOTIATION:
                logging.info("Didn't expect a Version Negotiation packet.")
                raise FailedTestException
            packet_size = int(p.udp.length) - 8  # subtract the UDP header length
            if packet_type == PacketType.INVALID:
                logging.debug("Couldn't determine packet type.")
                raise FailedTestException
            if direction == Direction.FROM_CLIENT:
                if packet_type is PacketType.HANDSHAKE:
                    raise PassedTestException
                if packet_type is PacketType.INITIAL:
                    client_sent += packet_size
                    allowed += 3 * packet_size
                    allowed_with_tolerance += 4 * packet_size
                    log_output.append(
                        "Received a {} byte Initial packet from the client. Amplification limit: {}".format(
                            packet_size, 3 * client_sent
                        )
                    )
            elif direction == Direction.FROM_SERVER:
                server_sent += packet_size
                log_output.append(
                    "Received a {} byte Handshake packet from the server. Total: {}".format(
                        packet_size, server_sent
                    )
                )
                if packet_size >= allowed_with_tolerance:
                    log_output.append("Server violated the amplification limit.")
                    raise FailedTestException
                if packet_size > allowed:
                    log_output.append(
                        "Server violated the amplification limit, but stayed within 3-4x amplification. Letting it slide."
                    )
                allowed_with_tolerance -= packet_size
                allowed -= packet_size
            else:
                logging.debug("Couldn't determine sender of packet.")
                raise FailedTestException

        res = TestResult.FAILED
        try:
            self._server_trace().for_each_raw_packet(proc_packet)
        except FailedTestException:
            res = TestResult.FAILED
        except PassedTestException:
            res = TestResult.SUCCEEDED

        log_level = logging.DEBUG
        if res == TestResult.FAILED:
            log_level = logging.INFO
        for msg in log_output:
            logging.log(log_level, msg)
        return res


class TestCaseBlackhole(TestCaseQuic):
    @staticmethod
    def name():
        return "blackhole"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def abbreviation():
        return "B"

    @staticmethod
    def desc():
        return "Transfer succeeds despite underlying network blacking out for a few seconds."

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "blackhole --delay=15ms --bandwidth=10Mbps --queue=25 --on=5s --off=2s"

    def get_paths_raw(self):
        self._files = [self._generate_random_file(10 * MB)]
        return self._files

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseKeyUpdate(TestCaseHandshake):
    @staticmethod
    def name():
        return "keyupdate"

    @staticmethod
    def testname(p: Perspective):
        if p is Perspective.CLIENT:
            return "keyupdate"
        return "transfer"

    @staticmethod
    def abbreviation():
        return "U"

    @staticmethod
    def desc():
        return "One of the two endpoints updates keys and the peer responds correctly."

    def get_paths_raw(self):
        self._files = [self._generate_random_file(3 * MB)]
        return self._files

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED

        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED

        client = {0: 0, 1: 0}
        server = {0: 0, 1: 0}
        try:

            def _get_key_phase(pkt) -> int:
                kp: str = pkt.key_phase.raw_value
                # when key_phase bit is set in a QUIC packet, certain versions
                # of wireshark (4.0.11, for example) have been seen to return the string value
                # "1" and certain other versions of wireshark return the string value "True".
                # here we deal with such values and return the integer value 1 for either of those.
                return 1 if kp in ["1", "True"] else 0

            def _proc_key_phase_cli(p):
                key_phase = _get_key_phase(p)
                client[key_phase] += 1

            def _proc_key_phase_srv(p):
                key_phase = _get_key_phase(p)
                server[key_phase] += 1

            self._client_trace().for_each_1rtt(_proc_key_phase_cli, Direction.FROM_CLIENT)
            self._server_trace().for_each_1rtt(_proc_key_phase_srv, Direction.FROM_SERVER)

        except Exception:
            logging.info(
                "Failed to read key phase bits. Potentially incorrect SSLKEYLOG?"
            )
            return TestResult.FAILED

        succeeded = client[1] * server[1] > 0

        log_level = logging.INFO
        if succeeded:
            log_level = logging.DEBUG

        logging.log(
            log_level,
            "Client sent %d key phase 0 and %d key phase 1 packets.",
            client[0],
            client[1],
        )
        logging.log(
            log_level,
            "Server sent %d key phase 0 and %d key phase 1 packets.",
            server[0],
            server[1],
        )
        if not succeeded:
            logging.info(
                "Expected to see packets sent with key phase 1 from both client and server."
            )
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseHandshakeLoss(TestCaseQuic):
    _num_runs = 50

    @staticmethod
    def name():
        return "handshakeloss"

    @staticmethod
    def testname(p: Perspective):
        return "multiconnect"

    @staticmethod
    def abbreviation():
        return "L1"

    @staticmethod
    def desc():
        return "Handshake completes under extreme packet loss."

    @staticmethod
    def timeout() -> int:
        return 300

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "drop-rate --delay=15ms --bandwidth=10Mbps --queue=25 --rate_to_server=30 --rate_to_client=30 --burst_to_server=3 --burst_to_client=3"

    def get_paths_raw(self):
        for _ in range(self._num_runs):
            self._files.append(self._generate_random_file(1 * KB))
        return self._files

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != self._num_runs:
            logging.info(
                "Expected %d handshakes. Got: %d", self._num_runs, num_handshakes
            )
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseTransferLoss(TestCaseQuic):
    @staticmethod
    def name():
        return "transferloss"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def abbreviation():
        return "L2"

    @staticmethod
    def desc():
        return "Transfer completes under moderate packet loss."

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "drop-rate --delay=15ms --bandwidth=10Mbps --queue=25 --rate_to_server=2 --rate_to_client=2 --burst_to_server=3 --burst_to_client=3"

    def get_paths_raw(self):
        # At a packet loss rate of 2% and a MTU of 1500 bytes, we can expect 27 dropped packets.
        self._files = [self._generate_random_file(2 * MB)]
        return self._files

    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED
        return TestResult.SUCCEEDED


class TestCaseHandshakeCorruption(TestCaseHandshakeLoss):
    @staticmethod
    def name():
        return "handshakecorruption"

    @staticmethod
    def abbreviation():
        return "C1"

    @staticmethod
    def desc():
        return "Handshake completes under extreme packet corruption."

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "corrupt-rate --delay=15ms --bandwidth=10Mbps --queue=25 --rate_to_server=30 --rate_to_client=30 --burst_to_server=3 --burst_to_client=3"


class TestCaseTransferCorruption(TestCaseTransferLoss):
    @staticmethod
    def name():
        return "transfercorruption"

    @staticmethod
    def abbreviation():
        return "C2"

    @staticmethod
    def desc():
        return "Transfer completes under moderate packet corruption."

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "corrupt-rate --delay=15ms --bandwidth=10Mbps --queue=25 --rate_to_server=2 --rate_to_client=2 --burst_to_server=3 --burst_to_client=3"


class TestCaseECN(TestCaseHandshake):
    @staticmethod
    def name():
        return "ecn"

    @staticmethod
    def abbreviation():
        return "E"

    def get_paths_raw(self):
        # Transfer a bit more data, so that QUIC implementations that do ECN validation after the
        # handshake have a chance to ACK some ECN marked packets.
        self._files = [self._generate_random_file(100 * KB)]
        return self._files


    def _check_ecn_any(self, e) -> bool:
        return e[ECN.ECT0] != 0 or e[ECN.ECT1] != 0

    def _check_ecn_marks(self, e) -> bool:
        return e[ECN.CE] == 0 and self._check_ecn_any(e)

    def _check_ack_ecn(self, p) -> bool:
        # NOTE: We only check whether the trace contains any ACK-ECN information, not whether it is valid
        if hasattr(p["quic"], "ack.ect0_count"):
            return True
        return False

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED

        result = super(TestCaseECN, self).check()
        if result != TestResult.SUCCEEDED:
            return result

        ecn = [0] * (max(ECN) + 1)
        has_ack_ecn = False

        def count_ecn(p):
            e = int(getattr(p["ip"], "dsfield.ecn"))
            ecn[e] += 1

        def collect_ecn(p):
            nonlocal  has_ack_ecn
            count_ecn(p)
            has_ack_ecn = has_ack_ecn or self._check_ack_ecn(p)

        self._client_trace()._for_each_packet(
            self._client_trace()._get_direction_filter(Direction.FROM_CLIENT) + " quic",
            collect_ecn
        )
        ack_ecn_client_ok = has_ack_ecn
        ecn_client_any_marked = self._check_ecn_any(ecn)
        ecn_client_all_ok = self._check_ecn_marks(ecn)

        logging.debug("Client ECN:")
        for e in ECN:
            logging.debug("%s %d", e, ecn[e])


        ecn = [0] * (max(ECN) + 1)
        has_ack_ecn = False
        self._server_trace()._for_each_packet(
            self._server_trace()._get_direction_filter(Direction.FROM_SERVER) + " quic",
            collect_ecn
        )

        ack_ecn_server_ok = has_ack_ecn
        ecn_server_any_marked = self._check_ecn_any(ecn)
        ecn_server_all_ok = self._check_ecn_marks(ecn)
        logging.debug("Server ECN:")
        for e in ECN:
            logging.debug("%s %d", e, ecn[e])

        if ecn_client_any_marked is False:
            logging.info("Client did not mark any packets ECT(0) or ECT(1)")
        else:
            if ack_ecn_server_ok is False:
                logging.info("Server did not send any ACK-ECN frames")
            elif ecn_client_all_ok is False:
                logging.info(
                    "Not all client packets were consistently marked with ECT(0) or ECT(1)"
                )

        if ecn_server_any_marked is False:
            logging.info("Server did not mark any packets ECT(0) or ECT(1)")
        else:
            if ack_ecn_client_ok is False:
                logging.info("Client did not send any ACK-ECN frames")
            elif ecn_server_all_ok is False:
                logging.info(
                    "Not all server packets were consistently marked with ECT(0) or ECT(1)"
                )

        if (
            ecn_client_all_ok
            and ecn_server_all_ok
            and ack_ecn_client_ok
            and ack_ecn_server_ok
        ):
            return TestResult.SUCCEEDED
        return TestResult.FAILED


class TestCasePortRebinding(TestCaseTransfer):
    @staticmethod
    def name():
        return "rebind-port"

    @staticmethod
    def abbreviation():
        return "BP"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def desc():
        return "Transfer completes under frequent port rebindings on the client side."

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(10 * MB),
        ]
        return self._files

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return "rebind --delay=15ms --bandwidth=10Mbps --queue=25 --first-rebind=1s --rebind-freq=5s"

    @staticmethod
    def _addr(p: List, which: str) -> str:
        return (
            getattr(p["ipv6"], which)
            if "IPV6" in str(p.layers)
            else getattr(p["ip"], which)
        )

    @staticmethod
    def _path(p: List) -> Tuple[str, int, str, int]:
        return (
            TestCasePortRebinding._addr(p, "src"), int(getattr(p["udp"], "srcport")),
            TestCasePortRebinding._addr(p, "dst"), int(getattr(p["udp"], "dstport")),
        )

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED

        result = super(TestCasePortRebinding, self).check()
        if result != TestResult.SUCCEEDED:
            return result

        cur = None
        last = None
        paths = set()
        challenges = set()
        responses = list()

        def collect_challenges(p):
            nonlocal cur, last, paths
            cur = self._path(p)
            if last is None:
                last = cur
                return

            if last != cur and cur not in paths:
                paths.add(last)
                last = cur
                # Packet on new path, should have a PATH_CHALLENGE frame
                if hasattr(p["quic"], "path_challenge.data") is False:
                    logging.info(
                        "First server packet on new path %s did not contain a PATH_CHALLENGE frame",
                        cur,
                    )
                    logging.info(p["quic"])
                    raise FailedTestException()
                else:
                    challenges.add(getattr(p["quic"], "path_challenge.data"))

        def collect_resp(p):
            if hasattr(p["quic"], "path_response.data"):
                responses.append(getattr(p["quic"], "path_response.data"))

        try:
            self._server_trace()._for_each_packet(
                self._server_trace()._get_direction_filter(Direction.FROM_SERVER) + " quic",
                collect_challenges
            )
        except FailedTestException:
            return TestResult.FAILED

        paths.add(cur)

        logging.info("Server saw these paths used: %s", paths)
        if len(paths) <= 1:
            logging.info("Server saw only a single path in use; test broken?")
            return TestResult.FAILED

        try:
            self._client_trace()._for_each_packet(
                self._client_trace()._get_direction_filter(Direction.FROM_CLIENT) + " quic",
                collect_resp
            )
        except FailedTestException:
            return TestResult.FAILED

        logging.debug("Path responses: %s", responses)

        unresponded = [c for c in challenges if c not in responses]
        if unresponded != []:
            logging.info("PATH_CHALLENGE without a PATH_RESPONSE: %s", unresponded)
            return TestResult.FAILED

        return TestResult.SUCCEEDED


class TestCaseAddressRebinding(TestCasePortRebinding):
    @staticmethod
    def name():
        return "rebind-addr"

    @staticmethod
    def abbreviation():
        return "BA"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def desc():
        return "Transfer completes under frequent IP address and port rebindings on the client side."

    @staticmethod
    def scenario() -> str:
        """Scenario for the ns3 simulator"""
        return (
            super(TestCaseAddressRebinding, TestCaseAddressRebinding).scenario()
            + " --rebind-addr"
        )

    def check(self) -> TestResult:
        super().check()
        if not self._keylog_file():
            logging.info("Can't check test result. SSLKEYLOG required.")
            return TestResult.UNSUPPORTED

        ips = set()
        def collect_ips(p):
            ip_vers = "ip"
            if "IPV6" in str(p.layers):
                ip_vers = "ipv6"
            ips.add(getattr(p[ip_vers], "dst"))
            ips.add(getattr(p[ip_vers], "dst"))

        self._server_trace()._for_each_packet(
            self._server_trace()._get_direction_filter(Direction.FROM_SERVER) + " quic",
            collect_ips
        )

        logging.info("Server saw these client addresses: %s", ips)
        if len(ips) <= 1:
            logging.info(
                "Server saw only a single client IP address in use; test broken?"
            )
            return TestResult.FAILED

        result = super(TestCaseAddressRebinding, self).check()
        if result != TestResult.SUCCEEDED:
            return result

        return TestResult.SUCCEEDED


class TestCaseIPv6(TestCaseTransfer):
    @staticmethod
    def name():
        return "ipv6"

    @staticmethod
    def abbreviation():
        return "6"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def urlprefix() -> str:
        return "https://server6:443/"

    @staticmethod
    def desc():
        return "A transfer across an IPv6-only network succeeded."

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(5 * KB),
            self._generate_random_file(10 * KB),
        ]
        return self._files

    def check(self) -> TestResult:
        super().check()
        result = super(TestCaseIPv6, self).check()
        if result != TestResult.SUCCEEDED:
            return result

        def check_no_ip_v4(p):
            logging.info("Packet trace contains IPv4 packets.")
            raise FailedTestException()

        try:
            self._server_trace()._for_each_packet(
                self._server_trace()._get_direction_filter(Direction.FROM_SERVER)
                + " quic && ip",
                check_no_ip_v4
            )
        except FailedTestException:
            return TestResult.FAILED

        return TestResult.SUCCEEDED


class TestCaseConnectionMigration(TestCasePortRebinding):
    @staticmethod
    def name():
        return "connectionmigration"

    @staticmethod
    def abbreviation():
        return "CM"

    @staticmethod
    def testname(p: Perspective):
        if p is Perspective.SERVER:
            # Server needs to send preferred addresses
            return "connectionmigration"
        return "transfer"

    @staticmethod
    def desc():
        return "A transfer succeeded during which the client performed an active migration."

    @staticmethod
    def scenario() -> str:
        return super(TestCaseTransfer, TestCaseTransfer).scenario()

    @staticmethod
    def urlprefix() -> str:
        """URL prefix"""
        return "https://server46:443/"

    def get_paths_raw(self):
        self._files = [
            self._generate_random_file(2 * MB),
        ]
        return self._files

    def check(self) -> TestResult:
        super().check()
        # The parent check() method ensures that the client changed addresses
        # and that PATH_CHALLENGE/RESPONSE frames were sent and received
        result = super(TestCaseConnectionMigration, self).check()
        if result != TestResult.SUCCEEDED:
            return result

        last = None
        paths = set()
        dcid = None

        def check_packet(p):
            nonlocal last, dcid
            cur = self._path(p)
            if last is None:
                last = cur
                dcid = getattr(p["quic"], "dcid")
                return

            if last != cur and cur not in paths:
                paths.add(last)
                last = cur
                # packet to different IP/port, should have a new DCID
                if dcid == getattr(p["quic"], "dcid"):
                    logging.info(
                        "First client packet during active migration to %s used previous DCID %s",
                        cur,
                        dcid,
                    )
                    logging.info(p["quic"])
                    raise FailedTestException()
                dcid = getattr(p["quic"], "dcid")
                logging.info(
                    "DCID changed to %s during active migration to %s", dcid, cur
                )

        try:
            self._client_trace()._for_each_packet(
                self._client_trace()._get_direction_filter(Direction.FROM_CLIENT) + " quic",
                check_packet
            )
        except FailedTestException:
            return TestResult.FAILED

        return TestResult.SUCCEEDED


class TestCaseV2(TestCaseQuic):
    @staticmethod
    def name():
        return "v2"

    @staticmethod
    def abbreviation():
        return "V2"

    @staticmethod
    def desc():
        return "Server should select QUIC v2 in compatible version negotiation."

    def get_paths_raw(self):
        self._files = [self._generate_random_file(1 * KB)]
        return self._files

    def check(self) -> TestResult:
        super().check()
        # Client should initially send QUIC v1 packet.  It may send
        # QUIC v2 packet.

        versions = set()
        def _add_packet_version(p):
            versions.add(hex(int(p.version, 0)))

        self._client_trace().for_each_initial(_add_packet_version, Direction.FROM_CLIENT)

        if QUIC_VERSION not in versions:
            logging.info(
                "Wrong version in client Initial. Expected %s, got %s",
                QUIC_VERSION,
                versions,
            )
            return TestResult.FAILED

        # Server Initial packets should have QUIC v2.  It may send
        # QUIC v1 packet before sending CRYPTO frame.
        versions.clear()
        self._server_trace().for_each_initial(_add_packet_version, Direction.FROM_SERVER)

        if QUIC_V2 not in versions:
            logging.info(
                "Wrong version in server Initial. Expected %s, got %s",
                QUIC_V2,
                versions,
            )
            return TestResult.FAILED

        # Client should use QUIC v2 for all Handshake packets.
        versions.clear()
        self._client_trace().for_each_handshake(_add_packet_version, Direction.FROM_CLIENT)

        if len(versions) != 1:
            logging.info(
                "Expected exactly one version in client Handshake. Got %s", versions
            )
            return TestResult.FAILED
        if QUIC_V2 not in versions:
            logging.info(
                "Wrong version in client Handshake. Expected %s, got %s",
                QUIC_V2,
                versions,
            )
            return TestResult.FAILED

        # Server should use QUIC v2 for all Handshake packets.
        versions.clear()
        self._server_trace().for_each_handshake(_add_packet_version, Direction.FROM_SERVER)

        if len(versions) != 1:
            logging.info(
                "Expected exactly one version in server Handshake. Got %s", versions
            )
            return TestResult.FAILED
        if QUIC_V2 not in versions:
            logging.info(
                "Wrong version in server Handshake. Expected %s, got %s",
                QUIC_V2,
                versions,
            )
            return TestResult.FAILED

        if not self._check_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED



class MeasurementGoodput(Measurement):
    FILESIZE = 10 * MB
    _result = 0.0

    @staticmethod
    def name():
        return "goodput"

    @staticmethod
    def unit() -> str:
        return "kbps"

    @staticmethod
    def testname(p: Perspective):
        return "transfer"

    @staticmethod
    def abbreviation():
        return "G"

    @staticmethod
    def desc():
        return "Measures connection goodput over a 10Mbps link."

    @staticmethod
    def repetitions() -> int:
        return 5

    def get_paths(self):
        return [self.urlprefix() + p for p in self.get_paths_raw()]

    def get_paths_raw(self):
        self._files = [self._generate_random_file(self.FILESIZE)]
        return self._files

    first = 0
    last = 0



    def check(self) -> TestResult:
        super().check()
        num_handshakes = self._count_handshakes()
        if num_handshakes != 1:
            logging.info("Expected exactly 1 handshake. Got: %d", num_handshakes)
            return TestResult.FAILED
        if not self._check_version_and_files():
            return TestResult.FAILED

        first = 0
        last = 0

        def collect_fist_last(p):
            nonlocal first, last
            if first == 0:
                first = p.sniff_time
            last = p.sniff_time

        self._client_trace().for_each_1rtt(
            None,
            Direction.FROM_SERVER,
            on_packet=collect_fist_last
        )

        if last - first == 0:
            return TestResult.FAILED
        time = (last - first) / timedelta(milliseconds=1)
        goodput = (8 * self.FILESIZE) / time
        logging.debug(
            "Transfering %d MB took %d ms. Goodput: %d kbps",
            self.FILESIZE / MB,
            time,
            goodput,
        )
        self._result = goodput
        return TestResult.SUCCEEDED

    def result(self) -> float:
        return self._result


class MeasurementCrossTraffic(MeasurementGoodput):
    FILESIZE = 25 * MB

    @staticmethod
    def name():
        return "crosstraffic"

    @staticmethod
    def abbreviation():
        return "C"

    @staticmethod
    def desc():
        return "Measures goodput over a 10Mbps link when competing with a TCP (cubic) connection."

    @staticmethod
    def timeout() -> int:
        return 180

    @staticmethod
    def additional_envs() -> List[str]:
        return ["IPERF_CONGESTION=cubic"]

    @staticmethod
    def additional_containers() -> List[str]:
        return ["iperf_server", "iperf_client"]


TESTCASES_QUIC = [
    TestCaseHandshake,
    TestCaseTransfer,
    TestCaseLongRTT,
    TestCaseChaCha20,
    TestCaseMultiplexing,
    TestCaseRetry,
    TestCaseResumption,
    TestCaseZeroRTT,
    TestCaseHTTP3,
    TestCaseBlackhole,
    TestCaseKeyUpdate,
    TestCaseECN,
    TestCaseAmplificationLimit,
    TestCaseHandshakeLoss,
    TestCaseTransferLoss,
    TestCaseHandshakeCorruption,
    TestCaseTransferCorruption,
    TestCaseIPv6,
    TestCaseV2,
    TestCasePortRebinding,
    TestCaseAddressRebinding,
    TestCaseConnectionMigration,
]

MEASUREMENTS = [
    MeasurementGoodput,
    MeasurementCrossTraffic,
]
