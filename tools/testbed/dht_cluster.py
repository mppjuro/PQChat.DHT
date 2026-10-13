"""
Isolated DHT Cluster orchestrating 100-300 BEP 5 / BEP 44 compliant nodes.
No connection to public DHT. Fully local Kademlia routing and configurable
adversary/Sybil node fraction with malicious observer logging.
"""

import os
import random
import socket
import asyncio
from typing import List, Dict, Optional, Tuple

from .dht_node import DhtNode, TelemetryLogger, QueryLogEntry
from . import ed25519


class DhtCluster:
    """
    Manages a local network of 100-300 Kademlia DHT nodes.
    Supports configurable size, Sybil fraction, and deterministic random seeding.
    """

    def __init__(
        self,
        num_nodes: int = 150,
        sybil_fraction: float = 0.0,
        base_port: int = 30000,
        host: str = "127.0.0.1",
        seed: int = 42
    ):
        if num_nodes < 10 or num_nodes > 500:
            raise ValueError(f"num_nodes should be between 10 and 500, got {num_nodes}")

        self.num_nodes = num_nodes
        self.sybil_fraction = sybil_fraction
        self.base_port = base_port
        self.host = host
        self.seed = seed
        self.rng = random.Random(seed)

        self.logger = TelemetryLogger()
        self.nodes: List[DhtNode] = []
        self.node_by_port: Dict[int, DhtNode] = {}
        self.node_by_id: Dict[bytes, DhtNode] = {}

        self._build_cluster()

    def _build_cluster(self):
        """Constructs the nodes with uniform Node ID distribution and Sybil assignment."""
        num_sybils = int(self.num_nodes * self.sybil_fraction)
        sybil_indices = set(self.rng.sample(range(self.num_nodes), num_sybils)) if num_sybils > 0 else set()

        for i in range(self.num_nodes):
            port = self.base_port + i
            # Generate deterministic 20-byte Node ID
            node_id_seed = f"node_seed_{self.seed}_{i}".encode("utf-8")
            node_id = ed25519.compute_target(node_id_seed)

            is_malicious = (i in sybil_indices)
            node = DhtNode(
                node_id=node_id,
                ip=self.host,
                port=port,
                is_malicious=is_malicious,
                logger=self.logger
            )
            self.nodes.append(node)
            self.node_by_port[port] = node
            self.node_by_id[node_id] = node

        # Form Kademlia routing tables
        self._bootstrap_routing_tables()

    def _bootstrap_routing_tables(self):
        """Populates routing tables across all nodes using Kademlia XOR metric."""
        for i, node in enumerate(self.nodes):
            # Bootstrap into Node 0 and random sample of other nodes
            sample_candidates = [other for j, other in enumerate(self.nodes) if j != i]
            # Ensure Node 0 is known
            if i != 0:
                node.add_peer(self.nodes[0].node_id, self.nodes[0].ip, self.nodes[0].port)

            # Add sample of other peers to populate buckets
            sample_size = min(len(sample_candidates), 24)
            for other in self.rng.sample(sample_candidates, sample_size):
                node.add_peer(other.node_id, other.ip, other.port)

    def get_bootstrap_node(self) -> Tuple[str, int]:
        """Returns the primary bootstrap address (Node 0)."""
        return (self.nodes[0].ip, self.nodes[0].port)

    def get_closest_storage_nodes(self, target: bytes, count: int = 8) -> List[DhtNode]:
        """Returns the count closest nodes in the cluster to target."""
        from .dht_node import xor_distance
        sorted_nodes = sorted(
            self.nodes,
            key=lambda n: xor_distance(n.node_id, target)
        )
        return sorted_nodes[:count]

    def is_target_intercepted_by_sybil(self, target: bytes, k: int = 8) -> Tuple[bool, int]:
        """
        Checks whether at least one malicious Sybil node is among the K closest
        storage nodes for the given target in the cluster.
        Returns (is_intercepted, count_of_sybils_in_k).
        """
        closest = self.get_closest_storage_nodes(target, count=k)
        sybils = [n for n in closest if n.is_malicious]
        return (len(sybils) > 0, len(sybils))

    def process_packet(
        self,
        raw_bytes: bytes,
        dest_port: int,
        sender_ip: str,
        sender_port: int,
        timestamp_ms: int
    ) -> Optional[bytes]:
        """Direct in-process packet dispatch to the target virtual node."""
        node = self.node_by_port.get(dest_port)
        if node is None:
            return None
        return node.handle_krpc_message(
            raw_bytes=raw_bytes,
            sender_ip=sender_ip,
            sender_port=sender_port,
            current_time_ms=timestamp_ms
        )


class UdpClusterServerProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP protocol for running the DHT cluster as a real network service."""
    def __init__(self, cluster: DhtCluster, port: int):
        self.cluster = cluster
        self.port = port
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        import time
        now_ms = int(time.time() * 1000)
        sender_ip, sender_port = addr
        resp_bytes = self.cluster.process_packet(
            raw_bytes=data,
            dest_port=self.port,
            sender_ip=sender_ip,
            sender_port=sender_port,
            timestamp_ms=now_ms
        )
        if resp_bytes and self.transport:
            self.transport.sendto(resp_bytes, addr)
