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
        DhtNodeCacheEntity::class,
        PendingRekeyOfferEntity::class,
        SkippedKeyEntity::class
    ],
    version = 8,
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

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "pqchat_dht.db"
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8)
                    .fallbackToDestructiveMigrationOnDowngrade()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
