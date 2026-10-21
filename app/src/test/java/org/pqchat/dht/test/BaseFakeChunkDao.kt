package org.pqchat.dht.test

import org.pqchat.dht.data.db.ChunkDao
import org.pqchat.dht.data.db.ChunkEntity
import org.pqchat.dht.data.db.PendingChunkTransferEntity

open class BaseFakeChunkDao : ChunkDao {
    val chunks = mutableListOf<ChunkEntity>()
    val pendingTransfers = mutableListOf<PendingChunkTransferEntity>()

    override suspend fun insertChunk(chunk: ChunkEntity) {
        chunks.removeAll { it.transferId == chunk.transferId && it.chunkIndex == chunk.chunkIndex }
        chunks.add(chunk)
    }

    override suspend fun getChunksForTransfer(transferId: String): List<ChunkEntity> =
        chunks.filter { it.transferId == transferId }.sortedBy { it.chunkIndex }

    override suspend fun countChunks(transferId: String): Int =
        chunks.count { it.transferId == transferId }

    override suspend fun deleteChunks(transferId: String) {
        chunks.removeAll { it.transferId == transferId }
    }

    override suspend fun getExistingChunkIndices(transferId: String): List<Int> =
        chunks.filter { it.transferId == transferId }.map { it.chunkIndex }.sorted()

    override suspend fun insertPendingTransfer(transfer: PendingChunkTransferEntity) {
        pendingTransfers.removeAll { it.transferId == transfer.transferId }
        pendingTransfers.add(transfer)
    }

    override suspend fun getPendingTransfer(transferId: String): PendingChunkTransferEntity? =
        pendingTransfers.firstOrNull { it.transferId == transferId }

    override suspend fun getPendingTransfersForContact(contactId: String): List<PendingChunkTransferEntity> =
        pendingTransfers.filter { it.contactId == contactId }.sortedBy { it.createdAt }

    override suspend fun getAllPendingTransfers(): List<PendingChunkTransferEntity> =
        pendingTransfers.sortedBy { it.createdAt }

    override suspend fun updateMissingIndices(transferId: String, missingIndices: org.pqchat.dht.data.db.EncryptedText) {
        val existing = pendingTransfers.firstOrNull { it.transferId == transferId } ?: return
        val bound = org.pqchat.dht.data.db.EncryptedText(
            raw = missingIndices.raw,
            boundTable = "pending_chunk_transfers",
            boundId = transferId,
            boundColumn = "missingIndices"
        )
        val updated = existing.copy(missingIndices = bound)
        pendingTransfers.removeAll { it.transferId == transferId }
        pendingTransfers.add(updated)
    }

    override suspend fun deletePendingTransfer(transferId: String) {
        pendingTransfers.removeAll { it.transferId == transferId }
    }

    override suspend fun deleteExpiredChunks(now: Long) {
        val expiredIds = pendingTransfers.filter { it.expiresAt < now }.map { it.transferId }.toSet()
        chunks.removeAll { it.transferId in expiredIds }
    }

    override suspend fun deleteExpiredPendingTransfers(now: Long) {
        pendingTransfers.removeAll { it.expiresAt < now }
    }
}
