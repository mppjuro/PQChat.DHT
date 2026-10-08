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
    version = 5,
    exportSchema = false
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

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "pqchat_dht.db"
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
                    .fallbackToDestructiveMigrationOnDowngrade()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
