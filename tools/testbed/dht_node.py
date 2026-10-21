"""
BEP 5 and BEP 44 compliant Kademlia DHT Node implementation for isolated testbed.
Supports mutable records storage (put/get), token authentication, Ed25519 verification,
Kademlia XOR routing, and malicious observer telemetry logging.
"""

import os
import time
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

from . import bencode
from . import ed25519


def xor_distance(a: bytes, b: bytes) -> bytes:
    """Computes XOR distance between two 20-byte Node IDs / target hashes."""
    return bytes(x ^ y for x, y in zip(a, b))


def compare_distances(d1: bytes, d2: bytes) -> int:
    """Compares two distances: returns -1 if d1 < d2, 1 if d1 > d2, 0 if equal."""
    for b1, b2 in zip(d1, d2):
        if b1 < b2:
            return -1
        elif b1 > b2:
            return 1
    return 0


@dataclass
class DhtPeer:
    node_id: bytes
    ip: str
    port: int
    last_seen: float = 0.0

    def to_compact(self) -> bytes:
        """Serializes to standard BEP 5 compact node info (26 bytes: 20B id + 4B IPv4 + 2B port)."""
        import socket
        ip_bytes = socket.inet_aton(self.ip)
        port_bytes = self.port.to_bytes(2, "big")
        return self.node_id + ip_bytes + port_bytes

    @staticmethod
    def from_compact(data: bytes) -> "DhtPeer":
        import socket
        node_id = data[:20]
        ip = socket.inet_ntoa(data[20:24])
        port = int.from_bytes(data[24:26], "big")
        return DhtPeer(node_id=node_id, ip=ip, port=port)


@dataclass
class MutableRecord:
    v: bytes
    seq: int
    k: bytes
    sig: bytes
    salt: Optional[bytes]
    updated_at_ms: int


@dataclass
class QueryLogEntry:
    timestamp_ms: int
    client_ip: str
    client_port: int
    node_id_hex: str
    node_port: int
    query_type: str  # "ping", "find_node", "get", "put"
    target_hex: str  # hex of target if get/put or info_hash, else ""
    payload_size: int
    seq: int
    is_malicious: bool
    data_source: str = "MEASURED"


class TelemetryLogger:
    """Thread-safe collector for testbed telemetry logs."""
    def __init__(self):
        self.entries: List[QueryLogEntry] = []

    def log(self, entry: QueryLogEntry):
        self.entries.append(entry)

    def clear(self):
        self.entries.clear()

    def get_entries(self) -> List[QueryLogEntry]:
        return list(self.entries)


class DhtNode:
    """
    Virtual BEP 5 / BEP 44 DHT node.
    """
    K = 8  # Closest nodes factor per Kademlia specification

    def __init__(
        self,
        node_id: bytes,
        ip: str,
        port: int,
        is_malicious: bool = False,
        logger: Optional[TelemetryLogger] = None,
        byzantine_behavior: Optional[str] = None
    ):
        self.node_id = node_id
        self.ip = ip
        self.port = port
        self.is_malicious = is_malicious
        self.logger = logger
        self.byzantine_behavior = byzantine_behavior

        # Routing table: list of known DhtPeers
        self.peers: Dict[bytes, DhtPeer] = {}

        # BEP 44 Mutable item storage: target_hex -> MutableRecord
        self.storage: Dict[str, MutableRecord] = {}

    def add_peer(self, peer_id: bytes, ip: str, port: int):
        if peer_id == self.node_id:
            return
        self.peers[peer_id] = DhtPeer(node_id=peer_id, ip=ip, port=port, last_seen=time.time())

    def find_closest_nodes(self, target: bytes, count: int = 8) -> List[DhtPeer]:
        """Finds closest known peers sorted by XOR distance to target."""
        sorted_peers = sorted(
            self.peers.values(),
            key=lambda p: xor_distance(p.node_id, target)
        )
        return sorted_peers[:count]

    def _generate_token(self, sender_ip: str) -> bytes:
        """Generates an 8-byte write token bound to sender IP and local Node ID."""
        h = hashlib.sha1(sender_ip.encode("ascii") + self.node_id).digest()
        return h[:8]

    def _validate_token(self, token: bytes, sender_ip: str) -> bool:
        expected = self._generate_token(sender_ip)
        return token == expected

    def handle_krpc_message(
        self,
        raw_bytes: bytes,
        sender_ip: str,
        sender_port: int,
        current_time_ms: int
    ) -> Optional[bytes]:
        """
        Parses incoming KRPC UDP packet, updates routing table, processes query,
        logs event if malicious observer, and returns response bencoded bytes.
        """
        try:
            msg = bencode.bdecode(raw_bytes)
        except Exception:
            return None

        if not isinstance(msg, dict):
            return None

        tx_id = msg.get("t")
        msg_type = msg.get("y")

        if msg_type == b"q" or msg_type == "q":
            q_method = msg.get("q")
            if isinstance(q_method, bytes):
                q_method = q_method.decode("utf-8", "ignore")
            args = msg.get("a", {})
            if not isinstance(args, dict):
                args = {}

            # Update routing table with sender's announced node ID
            sender_node_id = args.get("id")
            if isinstance(sender_node_id, bytes) and len(sender_node_id) == 20:
                self.add_peer(sender_node_id, sender_ip, sender_port)

            target_hex = ""
            payload_size = len(raw_bytes)
            seq_val = -1

            resp_data: Dict[str, Any] = {"id": self.node_id}

            if q_method == "ping":
                # BEP 5 ping response: {"id": node_id}
                pass

            elif q_method == "find_node":
                # BEP 5 find_node response: {"id": node_id, "nodes": compact_nodes}
                target = args.get("target")
                if isinstance(target, bytes) and len(target) == 20:
                    target_hex = target.hex()
                    closest = self.find_closest_nodes(target, count=self.K)
                    compact_nodes = b"".join(p.to_compact() for p in closest)
                    resp_data["nodes"] = compact_nodes

            elif q_method == "get":
                # BEP 44 get query
                target = args.get("target")
                if isinstance(target, bytes) and len(target) == 20:
                    target_hex = target.hex()
                    token = self._generate_token(sender_ip)
                    resp_data["token"] = token

                    if self.byzantine_behavior == "withhold_get":
                        # Byzantine Withholding Attack: do not return record
                        resp_data["nodes"] = b""
                    elif target_hex in self.storage:
                        rec = self.storage[target_hex]
                        v_out = rec.v
                        sig_out = rec.sig
                        k_out = rec.k

                        if self.byzantine_behavior == "mutate_bit_flip" and len(v_out) > 0:
                            v_arr = bytearray(v_out)
                            v_arr[0] ^= 0x01
                            v_out = bytes(v_arr)
                        elif self.byzantine_behavior == "mutate_bad_signature" and len(sig_out) > 0:
                            sig_arr = bytearray(sig_out)
                            sig_arr[0] ^= 0xFF
                            sig_out = bytes(sig_arr)
                        elif self.byzantine_behavior == "mutate_bad_key" and len(k_out) > 0:
                            k_arr = bytearray(k_out)
                            k_arr[0] ^= 0xFF
                            k_out = bytes(k_arr)
                        elif self.byzantine_behavior == "inject_bad_size_0b":
                            v_out = b""
                        elif self.byzantine_behavior == "inject_bad_size_899b":
                            v_out = rec.v[:899]
                        elif self.byzantine_behavior == "inject_bad_size_1000b":
                            v_out = rec.v + b"\x00" * 100

                        resp_data["v"] = v_out
                        resp_data["k"] = k_out
                        resp_data["sig"] = sig_out
                        resp_data["seq"] = rec.seq
                        seq_val = rec.seq
                        if rec.salt:
                            resp_data["salt"] = rec.salt
                    else:
                        closest = self.find_closest_nodes(target, count=self.K)
                        compact_nodes = b"".join(p.to_compact() for p in closest)
                        resp_data["nodes"] = compact_nodes

            elif q_method == "put":
                # BEP 44 put query
                v = args.get("v")
                k = args.get("k")
                sig = args.get("sig")
                seq = args.get("seq", 0)
                salt = args.get("salt")
                token = args.get("token")

                if (
                    isinstance(v, bytes)
                    and isinstance(k, bytes)
                    and isinstance(sig, bytes)
                    and isinstance(token, bytes)
                    and len(v) <= 1000
                    and len(k) == 32
                    and len(sig) == 64
                ):
                    seq_val = int(seq)
                    salt_bytes = salt if isinstance(salt, bytes) else None

                    # Byzantine Drop Attack: accept token but do not store
                    if self.byzantine_behavior == "drop_put":
                        pass
                    # Verify write token
                    elif self._validate_token(token, sender_ip):
                        # Verify Ed25519 signature
                        sign_data = bencode.encode_bep44_sign_data(v, seq_val, salt_bytes)
                        if ed25519.verify(k, sign_data, sig):
                            target_bytes = ed25519.compute_target(k, salt_bytes)
                            target_hex = target_bytes.hex()

                            # Check seq freshness
                            existing = self.storage.get(target_hex)
                            # Byzantine Tombstone Suppression / Sequence Rollback: ignore seq + 1 tombstone updates
                            if self.byzantine_behavior == "suppress_tombstone" and existing is not None and seq_val > existing.seq:
                                pass # preserve stale record
                            elif existing is None or seq_val >= existing.seq:
                                self.storage[target_hex] = MutableRecord(
                                    v=v,
                                    seq=seq_val,
                                    k=k,
                                    sig=sig,
                                    salt=salt_bytes,
                                    updated_at_ms=current_time_ms
                                )

            # Log event if malicious or observer logging enabled
            if (self.is_malicious or (self.logger is not None)) and self.logger is not None:
                entry = QueryLogEntry(
                    timestamp_ms=current_time_ms,
                    client_ip=sender_ip,
                    client_port=sender_port,
                    node_id_hex=self.node_id.hex(),
                    node_port=self.port,
                    query_type=q_method or "unknown",
                    target_hex=target_hex,
                    payload_size=payload_size,
                    seq=seq_val,
                    is_malicious=self.is_malicious,
                    data_source="SIMULATED" if ed25519.is_fast_mode() else "MEASURED"
                )
                self.logger.log(entry)

            if self.byzantine_behavior == "corrupt_bencode":
                # Return corrupted/truncated bencode dictionary
                return b"d1:t2:aa1:y1:r1:rd2:id20:MALFORMED_BENCODE_BROKEN"

            resp_packet = {
                "t": tx_id if tx_id is not None else b"aa",
                "y": "r",
                "r": resp_data
            }
            return bencode.bencode(resp_packet)

        return None
