package org.pqchat.dht.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        ContactEntity::class,
        MessageEntity::class,
        ChunkEntity::class,
        PendingChunkTransferEntity::class,
        DhtNodeCacheEntity::class,
        PendingRekeyOfferEntity::class,
        SkippedKeyEntity::class,
        GroupEntity::class,
        GroupMemberEntity::class
    ],
    version = 15,
    exportSchema = true
)
@TypeConverters(KeystoreConverters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun chunkDao(): ChunkDao
    abstract fun dhtNodeCacheDao(): DhtNodeCacheDao
    abstract fun pendingRekeyOfferDao(): PendingRekeyOfferDao
    abstract fun skippedKeyDao(): SkippedKeyDao
    abstract fun groupDao(): GroupDao
    abstract fun groupMemberDao(): GroupMemberDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'CONFIRMED_DHT'")
                db.execSQL("ALTER TABLE messages ADD COLUMN retryCount INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN lastAttemptTimestamp INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE contacts ADD COLUMN rekeyEpoch INTEGER NOT NULL DEFAULT 0")
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS pending_rekey_offers (
                        contactId TEXT NOT NULL PRIMARY KEY,
                        epoch INTEGER NOT NULL,
                        skNew BLOB NOT NULL,
                        pkNew BLOB NOT NULL,
                        offerSeqNum INTEGER NOT NULL,
                        createdAt INTEGER NOT NULL
                    )
                """.trimIndent())
            }
        }

        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE contacts ADD COLUMN receivedBitmapBase INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE contacts ADD COLUMN receivedBitmap BLOB NOT NULL DEFAULT (zeroblob(128))")
                db.execSQL("ALTER TABLE messages ADD COLUMN seqEpoch INTEGER NOT NULL DEFAULT 0")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_contactId_seqEpoch_seqNum ON messages (contactId, seqEpoch, seqNum)")
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS skipped_keys (
                        contactId TEXT NOT NULL,
                        slotIndex INTEGER NOT NULL,
                        msgKey BLOB NOT NULL,
                        target BLOB NOT NULL,
                        edPrivateKeySeed BLOB NOT NULL,
                        createdAt INTEGER NOT NULL,
                        expiresAt INTEGER NOT NULL,
                        PRIMARY KEY (contactId, slotIndex)
                    )
                """.trimIndent())
                db.execSQL("CREATE INDEX IF NOT EXISTS index_skipped_keys_expiresAt ON skipped_keys (expiresAt)")
            }
        }

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE contacts ADD COLUMN isInitiator INTEGER NOT NULL DEFAULT 1")
                db.execSQL("ALTER TABLE contacts ADD COLUMN sas TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE contacts ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN ackTarget BLOB")
                db.execSQL("ALTER TABLE messages ADD COLUMN ackRatchetKey BLOB")
                db.execSQL("ALTER TABLE messages ADD COLUMN slotTarget BLOB")
                db.execSQL("ALTER TABLE messages ADD COLUMN slotEdSeed BLOB")
            }
        }

        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // 1. Encrypt existing plain data in skipped_keys (msgKey, edPrivateKeySeed)
                val cursorSkipped = db.query("SELECT contactId, slotIndex, msgKey, edPrivateKeySeed FROM skipped_keys")
                while (cursorSkipped.moveToNext()) {
                    val contactId = cursorSkipped.getString(0)
                    val slotIndex = cursorSkipped.getInt(1)
                    val msgKey = cursorSkipped.getBlob(2)
                    val edPrivateKeySeed = cursorSkipped.getBlob(3)
                    val rowId = "${contactId}_${slotIndex}"
                    val encMsgKey = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(msgKey, "skipped_keys", rowId)
                    val encEdSeed = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(edPrivateKeySeed, "skipped_keys", rowId)
                    if (encMsgKey != null && encEdSeed != null) {
                        db.execSQL(
                            "UPDATE skipped_keys SET msgKey = ?, edPrivateKeySeed = ? WHERE contactId = ? AND slotIndex = ?",
                            arrayOf(encMsgKey, encEdSeed, contactId, slotIndex)
                        )
                    }
                }
                cursorSkipped.close()

                // 2. Encrypt existing plain data in pending_rekey_offers (skNew)
                val cursorOffers = db.query("SELECT contactId, skNew FROM pending_rekey_offers")
                while (cursorOffers.moveToNext()) {
                    val contactId = cursorOffers.getString(0)
                    val skNew = cursorOffers.getBlob(1)
                    val encSkNew = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(skNew, "pending_rekey_offers", contactId)
                    if (encSkNew != null) {
                        db.execSQL(
                            "UPDATE pending_rekey_offers SET skNew = ? WHERE contactId = ?",
                            arrayOf(encSkNew, contactId)
                        )
                    }
                }
                cursorOffers.close()

                // 3. Encrypt existing plain data in chunks (data)
                val cursorChunks = db.query("SELECT transferId, chunkIndex, data FROM chunks")
                while (cursorChunks.moveToNext()) {
                    val transferId = cursorChunks.getString(0)
                    val chunkIndex = cursorChunks.getInt(1)
                    val data = cursorChunks.getBlob(2)
                    val rowId = "${transferId}_${chunkIndex}"
                    val encData = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(data, "chunks", rowId)
                    if (encData != null) {
                        db.execSQL(
                            "UPDATE chunks SET data = ? WHERE transferId = ? AND chunkIndex = ?",
                            arrayOf(encData, transferId, chunkIndex)
                        )
                    }
                }
                cursorChunks.close()
            }
        }

        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE contacts ADD COLUMN isVerified INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS pending_chunk_transfers (
                        transferId TEXT NOT NULL PRIMARY KEY,
                        contactId TEXT NOT NULL,
                        seqNum INTEGER NOT NULL,
                        totalChunks INTEGER NOT NULL,
                        missingIndices TEXT NOT NULL,
                        baseEdSeed BLOB NOT NULL,
                        baseMsgKey BLOB NOT NULL,
                        direction TEXT NOT NULL,
                        isSelf INTEGER NOT NULL DEFAULT 0,
                        ackNum INTEGER NOT NULL DEFAULT 0,
                        timestampUTC INTEGER NOT NULL,
                        createdAt INTEGER NOT NULL,
                        expiresAt INTEGER NOT NULL
                    )
                """.trimIndent())
                db.execSQL("CREATE INDEX IF NOT EXISTS index_pending_chunk_transfers_contactId ON pending_chunk_transfers (contactId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_pending_chunk_transfers_expiresAt ON pending_chunk_transfers (expiresAt)")
            }
        }

        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS groups (
                        groupId TEXT NOT NULL PRIMARY KEY,
                        groupName TEXT NOT NULL,
                        myMemberId TEXT NOT NULL,
                        myChainKeyOut BLOB NOT NULL,
                        myCounterOut INTEGER NOT NULL,
                        groupEpoch INTEGER NOT NULL DEFAULT 0,
                        createdAt INTEGER NOT NULL,
                        lastActive INTEGER NOT NULL,
                        isActive INTEGER NOT NULL DEFAULT 1
                    )
                """.trimIndent())
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS group_members (
                        groupId TEXT NOT NULL,
                        memberId TEXT NOT NULL,
                        contactId TEXT,
                        memberName TEXT NOT NULL,
                        chainKeyIn BLOB NOT NULL,
                        counterIn INTEGER NOT NULL,
                        receivedBitmapBase INTEGER NOT NULL DEFAULT 0,
                        receivedBitmap BLOB NOT NULL,
                        joinedAt INTEGER NOT NULL,
                        isActive INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (groupId, memberId)
                    )
                """.trimIndent())
                db.execSQL("CREATE INDEX IF NOT EXISTS index_group_members_groupId ON group_members (groupId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_group_members_contactId ON group_members (contactId)")
                db.execSQL("ALTER TABLE messages ADD COLUMN senderMemberId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN senderName TEXT")
            }
        }

        val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // 1. Re-encrypt contacts:
                // - chainKeyOut and chainKeyIn from v1 (table+id) to v2 (table+id+column)
                // - encrypt plain metadata fields: name, sas, fingerprint
                val cursorContacts = db.query("SELECT id, name, chainKeyOut, chainKeyIn, sas, fingerprint FROM contacts")
                while (cursorContacts.moveToNext()) {
                    val id = cursorContacts.getString(0)
                    val rawName = cursorContacts.getString(1) ?: ""
                    val oldChainKeyOut = cursorContacts.getBlob(2)
                    val oldChainKeyIn = cursorContacts.getBlob(3)
                    val rawSas = cursorContacts.getString(4) ?: ""
                    val rawFingerprint = cursorContacts.getString(5) ?: ""

                    val plainChainKeyOut = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldChainKeyOut, "contacts", id) ?: oldChainKeyOut
                    } catch (_: Throwable) { oldChainKeyOut }
                    val plainChainKeyIn = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldChainKeyIn, "contacts", id) ?: oldChainKeyIn
                    } catch (_: Throwable) { oldChainKeyIn }

                    val newChainKeyOut = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainChainKeyOut, "contacts", id, "chainKeyOut")
                    val newChainKeyIn = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainChainKeyIn, "contacts", id, "chainKeyIn")

                    val encName = org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawName, "contacts", id, "name")
                    val encSas = org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawSas, "contacts", id, "sas")
                    val encFingerprint = org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawFingerprint, "contacts", id, "fingerprint")

                    db.execSQL(
                        "UPDATE contacts SET name = ?, chainKeyOut = ?, chainKeyIn = ?, sas = ?, fingerprint = ? WHERE id = ?",
                        arrayOf(encName, newChainKeyOut, newChainKeyIn, encSas, encFingerprint, id)
                    )
                }
                cursorContacts.close()

                // 2. Re-encrypt groups:
                // - groupName (plain text -> v2 EncryptedText)
                // - myChainKeyOut -> v2 ("groups", groupId, "myChainKeyOut")
                val cursorGroups = db.query("SELECT groupId, groupName, myChainKeyOut FROM groups")
                while (cursorGroups.moveToNext()) {
                    val groupId = cursorGroups.getString(0)
                    val rawGroupName = cursorGroups.getString(1) ?: ""
                    val oldKeyOut = cursorGroups.getBlob(2)

                    val plainKeyOut = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldKeyOut, "groups", groupId) ?: oldKeyOut
                    } catch (_: Throwable) { oldKeyOut }

                    val newKeyOut = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainKeyOut, "groups", groupId, "myChainKeyOut")
                    val encGroupName = org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawGroupName, "groups", groupId, "groupName")

                    db.execSQL(
                        "UPDATE groups SET groupName = ?, myChainKeyOut = ? WHERE groupId = ?",
                        arrayOf(encGroupName, newKeyOut, groupId)
                    )
                }
                cursorGroups.close()

                // 3. Re-encrypt group_members:
                // - memberName (plain text -> v2 EncryptedText)
                // - chainKeyIn -> v2 ("group_members", "${groupId}_${memberId}", "chainKeyIn")
                val cursorMembers = db.query("SELECT groupId, memberId, memberName, chainKeyIn FROM group_members")
                while (cursorMembers.moveToNext()) {
                    val groupId = cursorMembers.getString(0)
                    val memberId = cursorMembers.getString(1)
                    val rawMemberName = cursorMembers.getString(2) ?: ""
                    val oldKeyIn = cursorMembers.getBlob(3)
                    val rowId = "${groupId}_${memberId}"

                    val plainKeyIn = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldKeyIn, "group_members", rowId) ?: oldKeyIn
                    } catch (_: Throwable) { oldKeyIn }

                    val newKeyIn = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainKeyIn, "group_members", rowId, "chainKeyIn")
                    val encMemberName = org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawMemberName, "group_members", rowId, "memberName")

                    db.execSQL(
                        "UPDATE group_members SET memberName = ?, chainKeyIn = ? WHERE groupId = ? AND memberId = ?",
                        arrayOf(encMemberName, newKeyIn, groupId, memberId)
                    )
                }
                cursorMembers.close()

                // 4. Re-encrypt messages:
                // - bind textContent, imageBytes, ackRatchetKey, slotEdSeed, senderMemberId, senderName
                //   to rowId: "${contactId}_${seqEpoch}_${seqNum}_${isOutgoing}" and column name
                val cursorMessages = db.query("SELECT id, contactId, isOutgoing, seqEpoch, seqNum, textContent, imageBytes, ackRatchetKey, slotEdSeed, senderMemberId, senderName FROM messages")
                while (cursorMessages.moveToNext()) {
                    val id = cursorMessages.getLong(0)
                    val contactId = cursorMessages.getString(1)
                    val isOutgoing = cursorMessages.getInt(2) != 0
                    val seqEpoch = cursorMessages.getInt(3)
                    val seqNum = cursorMessages.getInt(4)
                    val oldTextContent = cursorMessages.getString(5)
                    val oldImageBytes = cursorMessages.getBlob(6)
                    val oldAckRatchetKey = cursorMessages.getBlob(7)
                    val oldSlotEdSeed = cursorMessages.getBlob(8)
                    val rawSenderMemberId = cursorMessages.getString(9)
                    val rawSenderName = cursorMessages.getString(10)

                    val newRowId = MessageEntity.computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing)

                    val newTextContentHex = if (oldTextContent != null) {
                        val plainText = try {
                            org.pqchat.dht.crypto.KeystoreCrypto.decryptString(oldTextContent) ?: oldTextContent
                        } catch (_: Throwable) { oldTextContent }
                        org.pqchat.dht.crypto.KeystoreCrypto.encryptString(plainText, "messages", newRowId, "textContent")
                    } else null

                    val newImageBytes = if (oldImageBytes != null) {
                        val plainImg = try {
                            org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldImageBytes) ?: oldImageBytes
                        } catch (_: Throwable) { oldImageBytes }
                        org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainImg, "messages", newRowId, "imageBytes")
                    } else null

                    val newAckRatchetKey = if (oldAckRatchetKey != null) {
                        val plainAck = try {
                            org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldAckRatchetKey) ?: oldAckRatchetKey
                        } catch (_: Throwable) { oldAckRatchetKey }
                        org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainAck, "messages", newRowId, "ackRatchetKey")
                    } else null

                    val newSlotEdSeed = if (oldSlotEdSeed != null) {
                        val plainSlot = try {
                            org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldSlotEdSeed) ?: oldSlotEdSeed
                        } catch (_: Throwable) { oldSlotEdSeed }
                        org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainSlot, "messages", newRowId, "slotEdSeed")
                    } else null

                    val encSenderMemberId = if (rawSenderMemberId != null) {
                        org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawSenderMemberId, "messages", newRowId, "senderMemberId")
                    } else null

                    val encSenderName = if (rawSenderName != null) {
                        org.pqchat.dht.crypto.KeystoreCrypto.encryptString(rawSenderName, "messages", newRowId, "senderName")
                    } else null

                    db.execSQL(
                        "UPDATE messages SET textContent = ?, imageBytes = ?, ackRatchetKey = ?, slotEdSeed = ?, senderMemberId = ?, senderName = ? WHERE id = ?",
                        arrayOf(newTextContentHex, newImageBytes, newAckRatchetKey, newSlotEdSeed, encSenderMemberId, encSenderName, id)
                    )
                }
                cursorMessages.close()

                // 5. Re-encrypt skipped_keys:
                // msgKey and edPrivateKeySeed with column binding
                val cursorSkipped = db.query("SELECT contactId, slotIndex, msgKey, edPrivateKeySeed FROM skipped_keys")
                while (cursorSkipped.moveToNext()) {
                    val contactId = cursorSkipped.getString(0)
                    val slotIndex = cursorSkipped.getInt(1)
                    val oldMsgKey = cursorSkipped.getBlob(2)
                    val oldEdSeed = cursorSkipped.getBlob(3)
                    val rowId = "${contactId}_${slotIndex}"

                    val plainMsgKey = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldMsgKey, "skipped_keys", rowId) ?: oldMsgKey
                    } catch (_: Throwable) { oldMsgKey }
                    val plainEdSeed = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldEdSeed, "skipped_keys", rowId) ?: oldEdSeed
                    } catch (_: Throwable) { oldEdSeed }

                    val newMsgKey = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainMsgKey, "skipped_keys", rowId, "msgKey")
                    val newEdSeed = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainEdSeed, "skipped_keys", rowId, "edPrivateKeySeed")

                    db.execSQL(
                        "UPDATE skipped_keys SET msgKey = ?, edPrivateKeySeed = ? WHERE contactId = ? AND slotIndex = ?",
                        arrayOf(newMsgKey, newEdSeed, contactId, slotIndex)
                    )
                }
                cursorSkipped.close()

                // 6. Re-encrypt pending_rekey_offers:
                // skNew with column binding "skNew"
                val cursorOffers = db.query("SELECT contactId, skNew FROM pending_rekey_offers")
                while (cursorOffers.moveToNext()) {
                    val contactId = cursorOffers.getString(0)
                    val oldSkNew = cursorOffers.getBlob(1)

                    val plainSkNew = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldSkNew, "pending_rekey_offers", contactId) ?: oldSkNew
                    } catch (_: Throwable) { oldSkNew }

                    val newSkNew = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainSkNew, "pending_rekey_offers", contactId, "skNew")

                    db.execSQL(
                        "UPDATE pending_rekey_offers SET skNew = ? WHERE contactId = ?",
                        arrayOf(newSkNew, contactId)
                    )
                }
                cursorOffers.close()

                // 7. Re-encrypt chunks:
                // data with column binding "data"
                val cursorChunks = db.query("SELECT transferId, chunkIndex, data FROM chunks")
                while (cursorChunks.moveToNext()) {
                    val transferId = cursorChunks.getString(0)
                    val chunkIndex = cursorChunks.getInt(1)
                    val oldData = cursorChunks.getBlob(2)
                    val rowId = "${transferId}_${chunkIndex}"

                    val plainData = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldData, "chunks", rowId) ?: oldData
                    } catch (_: Throwable) { oldData }

                    val newData = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainData, "chunks", rowId, "data")

                    db.execSQL(
                        "UPDATE chunks SET data = ? WHERE transferId = ? AND chunkIndex = ?",
                        arrayOf(newData, transferId, chunkIndex)
                    )
                }
                cursorChunks.close()

                // 8. Re-encrypt pending_chunk_transfers:
                // baseEdSeed and baseMsgKey with column names
                val cursorPendingTransfers = db.query("SELECT transferId, baseEdSeed, baseMsgKey FROM pending_chunk_transfers")
                while (cursorPendingTransfers.moveToNext()) {
                    val transferId = cursorPendingTransfers.getString(0)
                    val oldEdSeed = cursorPendingTransfers.getBlob(1)
                    val oldMsgKey = cursorPendingTransfers.getBlob(2)

                    val plainEdSeed = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldEdSeed, "pending_chunk_transfers", "${transferId}_seed") ?: oldEdSeed
                    } catch (_: Throwable) { oldEdSeed }
                    val plainMsgKey = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldMsgKey, "pending_chunk_transfers", "${transferId}_key") ?: oldMsgKey
                    } catch (_: Throwable) { oldMsgKey }

                    val newEdSeed = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainEdSeed, "pending_chunk_transfers", "${transferId}_seed", "baseEdSeed")
                    val newMsgKey = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainMsgKey, "pending_chunk_transfers", "${transferId}_key", "baseMsgKey")

                    db.execSQL(
                        "UPDATE pending_chunk_transfers SET baseEdSeed = ?, baseMsgKey = ? WHERE transferId = ?",
                        arrayOf(newEdSeed, newMsgKey, transferId)
                    )
                }
                cursorPendingTransfers.close()
            }
        }

        val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN ephemeralTtlSeconds INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN expiresAtTimestamp INTEGER")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_expiresAtTimestamp ON messages (expiresAtTimestamp)")
            }
        }

        val MIGRATION_12_13 = object : Migration(12, 13) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN reaction TEXT")
            }
        }

        val MIGRATION_13_14 = object : Migration(13, 14) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // 1. Recreate messages table with TEXT columns for ephemeralTtlSeconds, expiresAtTimestamp, reaction
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS messages_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        contactId TEXT NOT NULL,
                        isOutgoing INTEGER NOT NULL,
                        seqEpoch INTEGER NOT NULL,
                        seqNum INTEGER NOT NULL,
                        ackNum INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        textContent TEXT,
                        imageBytes BLOB,
                        status TEXT NOT NULL,
                        retryCount INTEGER NOT NULL,
                        lastAttemptTimestamp INTEGER NOT NULL,
                        ackTarget BLOB,
                        ackRatchetKey BLOB,
                        slotTarget BLOB,
                        slotEdSeed BLOB,
                        senderMemberId TEXT,
                        senderName TEXT,
                        ephemeralTtlSeconds TEXT NOT NULL,
                        expiresAtTimestamp TEXT,
                        reaction TEXT
                    )
                """.trimIndent())

                val converters = KeystoreConverters()

                val cursorMessages = db.query("""
                    SELECT id, contactId, isOutgoing, seqEpoch, seqNum, ackNum, timestamp,
                           textContent, imageBytes, status, retryCount, lastAttemptTimestamp,
                           ackTarget, ackRatchetKey, slotTarget, slotEdSeed,
                           senderMemberId, senderName, ephemeralTtlSeconds, expiresAtTimestamp, reaction
                    FROM messages
                """.trimIndent())

                while (cursorMessages.moveToNext()) {
                    val id = cursorMessages.getLong(0)
                    val contactId = cursorMessages.getString(1)
                    val isOutgoing = cursorMessages.getInt(2)
                    val seqEpoch = cursorMessages.getInt(3)
                    val seqNum = cursorMessages.getInt(4)
                    val ackNum = cursorMessages.getInt(5)
                    val timestamp = cursorMessages.getLong(6)
                    val textContent = if (cursorMessages.isNull(7)) null else cursorMessages.getString(7)
                    val imageBytes = if (cursorMessages.isNull(8)) null else cursorMessages.getBlob(8)
                    val status = cursorMessages.getString(9)
                    val retryCount = cursorMessages.getInt(10)
                    val lastAttemptTimestamp = cursorMessages.getLong(11)
                    val ackTarget = if (cursorMessages.isNull(12)) null else cursorMessages.getBlob(12)
                    val ackRatchetKey = if (cursorMessages.isNull(13)) null else cursorMessages.getBlob(13)
                    val slotTarget = if (cursorMessages.isNull(14)) null else cursorMessages.getBlob(14)
                    val slotEdSeed = if (cursorMessages.isNull(15)) null else cursorMessages.getBlob(15)
                    val senderMemberId = if (cursorMessages.isNull(16)) null else cursorMessages.getString(16)
                    val senderName = if (cursorMessages.isNull(17)) null else cursorMessages.getString(17)

                    val ephemeralTtlRaw = if (cursorMessages.isNull(18)) 0L else cursorMessages.getLong(18)
                    val expiresAtRaw = if (cursorMessages.isNull(19)) null else cursorMessages.getLong(19)
                    val reactionRaw = if (cursorMessages.isNull(20)) null else cursorMessages.getString(20)

                    val rowId = MessageEntity.computeMessageRowId(contactId, seqEpoch, seqNum, isOutgoing != 0)

                    val encEphemeralTtlHex = converters.toDatabaseLong(
                        EncryptedLong(ephemeralTtlRaw, "messages", rowId, "ephemeralTtlSeconds")
                    )!!

                    val encExpiresAtHex = expiresAtRaw?.let {
                        converters.toDatabaseLong(
                            EncryptedLong(it, "messages", rowId, "expiresAtTimestamp")
                        )
                    }

                    val encReactionHex = reactionRaw?.let {
                        val plainReaction = try {
                            val dec = org.pqchat.dht.crypto.KeystoreCrypto.decryptString(it, "messages", rowId, "reaction")
                            dec ?: it
                        } catch (_: Throwable) {
                            it
                        }
                        converters.toDatabaseText(
                            EncryptedText(plainReaction, "messages", rowId, "reaction")
                        )
                    }

                    db.execSQL("""
                        INSERT INTO messages_new (
                            id, contactId, isOutgoing, seqEpoch, seqNum, ackNum, timestamp,
                            textContent, imageBytes, status, retryCount, lastAttemptTimestamp,
                            ackTarget, ackRatchetKey, slotTarget, slotEdSeed,
                            senderMemberId, senderName, ephemeralTtlSeconds, expiresAtTimestamp, reaction
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """.trimIndent(), arrayOf(
                        id, contactId, isOutgoing, seqEpoch, seqNum, ackNum, timestamp,
                        textContent, imageBytes, status, retryCount, lastAttemptTimestamp,
                        ackTarget, ackRatchetKey, slotTarget, slotEdSeed,
                        senderMemberId, senderName, encEphemeralTtlHex, encExpiresAtHex, encReactionHex
                    ))
                }
                cursorMessages.close()

                db.execSQL("DROP TABLE messages")
                db.execSQL("ALTER TABLE messages_new RENAME TO messages")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_contactId_seqEpoch_seqNum ON messages (contactId, seqEpoch, seqNum)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_timestamp ON messages (timestamp)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_expiresAtTimestamp ON messages (expiresAtTimestamp)")

                // 2. Encrypt missingIndices in pending_chunk_transfers
                val cursorTransfers = db.query("SELECT transferId, missingIndices FROM pending_chunk_transfers")
                while (cursorTransfers.moveToNext()) {
                    val transferId = cursorTransfers.getString(0)
                    val rawMissing = cursorTransfers.getString(1)
                    val plainMissing = try {
                        val dec = org.pqchat.dht.crypto.KeystoreCrypto.decryptString(rawMissing, "pending_chunk_transfers", transferId, "missingIndices")
                        dec ?: rawMissing
                    } catch (_: Throwable) {
                        rawMissing
                    }
                    val encMissingHex = converters.toDatabaseText(
                        EncryptedText(plainMissing, "pending_chunk_transfers", transferId, "missingIndices")
                    )
                    db.execSQL(
                        "UPDATE pending_chunk_transfers SET missingIndices = ? WHERE transferId = ?",
                        arrayOf(encMissingHex, transferId)
                    )
                }
                cursorTransfers.close()

                // 3. Ensure chunks.data is encrypted with MAGIC_ROW_BOUND_V2 (table+id+column)
                val cursorChunks = db.query("SELECT transferId, chunkIndex, data FROM chunks")
                while (cursorChunks.moveToNext()) {
                    val transferId = cursorChunks.getString(0)
                    val chunkIndex = cursorChunks.getInt(1)
                    val oldData = cursorChunks.getBlob(2)
                    val rowId = "${transferId}_${chunkIndex}"

                    val plainData = try {
                        org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldData, "chunks", rowId, "data") ?: oldData
                    } catch (_: Throwable) {
                        try {
                            org.pqchat.dht.crypto.KeystoreCrypto.decrypt(oldData, "chunks", rowId) ?: oldData
                        } catch (_: Throwable) {
                            oldData
                        }
                    }

                    val newData = org.pqchat.dht.crypto.KeystoreCrypto.encrypt(plainData, "chunks", rowId, "data")
                    db.execSQL(
                        "UPDATE chunks SET data = ? WHERE transferId = ? AND chunkIndex = ?",
                        arrayOf(newData, transferId, chunkIndex)
                    )
                }
                cursorChunks.close()
            }
        }

        val MIGRATION_14_15 = object : Migration(14, 15) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN voiceBytes BLOB")
                db.execSQL("ALTER TABLE messages ADD COLUMN voiceDurationMs INTEGER NOT NULL DEFAULT 0")
            }
        }

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "pqchat_dht.db"
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12, MIGRATION_12_13, MIGRATION_13_14, MIGRATION_14_15)
                    .fallbackToDestructiveMigrationOnDowngrade(true)
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
