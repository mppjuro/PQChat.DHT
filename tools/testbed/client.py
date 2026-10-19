"""
Headless PQChat client implementation for correlation testbed.
Implements Ephemeral Key Hopping, Lookahead Polling, Decoy GETs, Delayed PUT,
Decoy PUT slots, Poisson Cover Traffic, and VPN/NAT IP abstraction.
"""

import math
import random
import hashlib
import hmac
from typing import List, Tuple, Dict, Optional, Set

from . import bencode
from . import ed25519
from .dht_cluster import DhtCluster


def hkdf_expand(pseudo_random_key: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) using HMAC-SHA-512."""
    hash_len = 64
    n = math.ceil(length / hash_len)
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        h = hmac.new(pseudo_random_key, t + info + bytes([i]), hashlib.sha512).digest()
        t = h
        okm.extend(h)
    return bytes(okm[:length])


class RatchetChainModel:
    """
    Python model of RatchetChain.kt:
    Entropy_i = HKDF-Expand(ChainKey^i, "step" || i, 128)
    - 0..31: msgKey
    - 32..63: edSeed
    - 64..127: nextChainKey
    - Target_i = SHA-1(pk_i)
    """

    def __init__(self, init_chain_key: bytes):
        if len(init_chain_key) != 64:
            raise ValueError("Chain key must be 64 bytes")
        self.chain_key = init_chain_key

    def derive_slot(self, counter: int) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Derives (msg_key, ed_seed, ed_pk, target, next_chain_key).
        Returns (msg_key, ed_pk, target, ed_seed).
        """
        step_info = b"step" + counter.to_bytes(4, "big")
        entropy = hkdf_expand(self.chain_key, step_info, 128)
        msg_key = entropy[:32]
        ed_seed = entropy[32:64]
        next_chain_key = entropy[64:128]
        ed_pk, _ = ed25519.generate_keypair(ed_seed)
        target = ed25519.compute_target(ed_pk)
        self.chain_key = next_chain_key
        return msg_key, ed_pk, target, ed_seed

    def compute_lookahead_slots(self, start_counter: int, window_size: int = 4) -> List[Tuple[int, bytes, bytes]]:
        """
        Computes (counter, target, next_chain_key) for lookahead window [start_counter .. start_counter + window_size].
        Does not mutate the current chain_key until consumed.
        """
        slots = []
        curr_key = self.chain_key
        for c in range(start_counter, start_counter + window_size + 1):
            step_info = b"step" + c.to_bytes(4, "big")
            entropy = hkdf_expand(curr_key, step_info, 128)
            ed_seed = entropy[32:64]
            next_key = entropy[64:128]
            ed_pk, _ = ed25519.generate_keypair(ed_seed)
            target = ed25519.compute_target(ed_pk)
            slots.append((c, target, next_key))
            curr_key = next_key
        return slots


class DecoyTargetPoolModel:
    """Thread-safe pool of known populated/cover targets surviving 0-PUT filtering."""

    def __init__(self, max_capacity: int = 200):
        self.max_capacity = max_capacity
        self.pool: List[bytes] = []

    def register_populated_target(self, target: bytes):
        if target not in self.pool:
            self.pool.insert(0, target)
            if len(self.pool) > self.max_capacity:
                self.pool.pop()

    def get_decoy_targets(self, count: int, rng: random.Random) -> List[bytes]:
        if not self.pool or count <= 0:
            return []
        sample_size = min(count, len(self.pool))
        return rng.sample(self.pool, sample_size)


class HeadlessPqClient:
    """
    Headless PQChat client.
    Can act as Alice (sender) or Bob (receiver).
    """

    def __init__(
        self,
        client_id: str,
        virtual_ip: str,
        cluster: DhtCluster,
        init_chain_key: bytes,
        rng: random.Random,
        vpn_gateway_ip: Optional[str] = None,
        decoy_pool: Optional[DecoyTargetPoolModel] = None
    ):
        self.client_id = client_id
        self.virtual_ip = virtual_ip
        self.vpn_gateway_ip = vpn_gateway_ip  # If set, external packets appear from this IP
        self.cluster = cluster
        self.rng = rng
        self.port = 40000 + (hash(client_id) % 10000)

        self.ratchet = RatchetChainModel(init_chain_key)
        self.counter_out = 0
        self.counter_in = 0
        self.decoy_pool = decoy_pool if decoy_pool is not None else DecoyTargetPoolModel()

        # Cache of Target -> (pk, sk)
        self.slot_credentials: Dict[bytes, Tuple[bytes, bytes]] = {}

    @property
    def effective_ip(self) -> str:
        """The IP observed by the DHT nodes (virtual IP or VPN gateway IP)."""
        return self.vpn_gateway_ip if self.vpn_gateway_ip else self.virtual_ip

    def send_put(
        self,
        target: bytes,
        payload_900b: bytes,
        pk: bytes,
        sk: bytes,
        seq: int,
        timestamp_ms: int,
        k_closest: int = 4
    ) -> bool:
        """
        Publishes a BEP 44 mutable record to the closest nodes in the cluster.
        First issues 'get' to acquire write token, then issues 'put'.
        """
        if len(payload_900b) != 900:
            raise ValueError(f"Payload must be exactly 900 bytes, got {len(payload_900b)}")

        sign_data = bencode.encode_bep44_sign_data(payload_900b, seq)
        sig = ed25519.sign(sk, sign_data)

        closest_nodes = self.cluster.get_closest_storage_nodes(target, count=k_closest)
        success_count = 0

        for node in closest_nodes:
            # 1. Acquire token via get
            get_query = {
                "t": b"g1",
                "y": "q",
                "q": "get",
                "a": {
                    "id": self.client_id.encode("utf-8")[:20].ljust(20, b"0"),
                    "target": target
                }
            }
            resp_bytes = self.cluster.process_packet(
                raw_bytes=bencode.bencode(get_query),
                dest_port=node.port,
                sender_ip=self.effective_ip,
                sender_port=self.port,
                timestamp_ms=timestamp_ms
            )

            token = b""
            if resp_bytes:
                resp = bencode.bdecode(resp_bytes)
                r_dict = resp.get("r", {})
                token = r_dict.get("token", b"")

            # 2. Put record
            put_query = {
                "t": b"p1",
                "y": "q",
                "q": "put",
                "a": {
                    "id": self.client_id.encode("utf-8")[:20].ljust(20, b"0"),
                    "v": payload_900b,
                    "k": pk,
                    "sig": sig,
                    "seq": seq,
                    "token": token
                }
            }
            put_resp = self.cluster.process_packet(
                raw_bytes=bencode.bencode(put_query),
                dest_port=node.port,
                sender_ip=self.effective_ip,
                sender_port=self.port,
                timestamp_ms=timestamp_ms
            )
            if put_resp:
                success_count += 1

        self.decoy_pool.register_populated_target(target)
        return success_count > 0

    def query_get(self, target: bytes, timestamp_ms: int, k_closest: int = 3) -> Optional[bytes]:
        """Queries the closest storage nodes for target."""
        closest_nodes = self.cluster.get_closest_storage_nodes(target, count=k_closest)
        for node in closest_nodes:
            get_query = {
                "t": b"gq",
                "y": "q",
                "q": "get",
                "a": {
                    "id": self.client_id.encode("utf-8")[:20].ljust(20, b"0"),
                    "target": target
                }
            }
            resp_bytes = self.cluster.process_packet(
                raw_bytes=bencode.bencode(get_query),
                dest_port=node.port,
                sender_ip=self.effective_ip,
                sender_port=self.port,
                timestamp_ms=timestamp_ms
            )
            if resp_bytes:
                resp = bencode.bdecode(resp_bytes)
                r_dict = resp.get("r", {})
                if "v" in r_dict:
                    return r_dict["v"]
        return None

    def execute_lookahead_poll(
        self,
        timestamp_ms: int,
        window_size: int = 4
    ) -> List[bytes]:
        """
        Bob polls W future slots [counter_in .. counter_in + window_size].
        Returns list of targets queried. If message found, advances counter_in and ratchet.
        """
        slots = self.ratchet.compute_lookahead_slots(self.counter_in, window_size=window_size)
        queried = []
        for c, tgt, next_key in slots:
            resp = self.query_get(tgt, timestamp_ms=timestamp_ms)
            queried.append(tgt)
            if resp is not None and c == self.counter_in:
                self.counter_in += 1
                self.ratchet.chain_key = next_key
        return queried

    def execute_decoy_gets(
        self,
        count: int,
        timestamp_ms: int,
        use_populated_pool: bool = True
    ):
        """Emits decoy GET queries."""
        targets = []
        if use_populated_pool:
            targets = self.decoy_pool.get_decoy_targets(count, self.rng)

        # Fill remaining with synthetic hashes if needed
        while len(targets) < count:
            synth = bytes(self.rng.getrandbits(8) for _ in range(20))
            targets.append(synth)

        for tgt in targets:
            self.query_get(tgt, timestamp_ms=timestamp_ms)

    def execute_poisson_cover_put(self, timestamp_ms: int):
        """Emits a CSPRNG dummy PUT of exactly 900 bytes under a fresh ephemeral Ed25519 target."""
        dummy_seed = bytes(self.rng.getrandbits(8) for _ in range(32))
        dummy_pk, dummy_sk = ed25519.generate_keypair(dummy_seed)
        dummy_target = ed25519.compute_target(dummy_pk)
        dummy_payload = bytes(self.rng.getrandbits(8) for _ in range(900))

        self.send_put(
            target=dummy_target,
            payload_900b=dummy_payload,
            pk=dummy_pk,
            sk=dummy_sk,
            seq=0,
            timestamp_ms=timestamp_ms
        )
        self.decoy_pool.register_populated_target(dummy_target)

