package org.pqchat.dht.test

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import org.pqchat.dht.data.db.ContactDao
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.db.EncryptedBlob
import org.pqchat.dht.data.db.EncryptedText

open class BaseFakeContactDao : ContactDao {
    val contacts = mutableMapOf<String, ContactEntity>()
    val flow = MutableStateFlow<List<ContactEntity>>(emptyList())

    override fun getAllContactsFlow(): Flow<List<ContactEntity>> = flow
    override suspend fun getContactById(id: String): ContactEntity? = contacts[id]

    override suspend fun insertOrUpdate(contact: ContactEntity) {
        contacts[contact.id] = contact
        flow.value = contacts.values.toList()
    }

    override suspend fun updateOutgoingState(id: String, counterOut: Int, chainKeyOut: EncryptedBlob) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut)
        flow.value = contacts.values.toList()
    }

    override suspend fun updateOutgoingStateAndEpoch(
        id: String,
        counterOut: Int,
        chainKeyOut: EncryptedBlob,
        rekeyEpoch: Long
    ) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(counterOut = counterOut, chainKeyOut = chainKeyOut, rekeyEpoch = rekeyEpoch)
        flow.value = contacts.values.toList()
    }

    override suspend fun updateIncomingState(id: String, counterIn: Int, chainKeyIn: EncryptedBlob) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn)
        flow.value = contacts.values.toList()
    }

    override suspend fun updateIncomingStateWithBitmap(
        id: String,
        counterIn: Int,
        chainKeyIn: EncryptedBlob,
        bitmapBase: Int,
        bitmap: ByteArray
    ) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(
            counterIn = counterIn,
            chainKeyIn = chainKeyIn,
            receivedBitmapBase = bitmapBase,
            receivedBitmap = bitmap
        )
        flow.value = contacts.values.toList()
    }

    override suspend fun updateIncomingStateAndEpoch(
        id: String,
        counterIn: Int,
        chainKeyIn: EncryptedBlob,
        rekeyEpoch: Long
    ) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(counterIn = counterIn, chainKeyIn = chainKeyIn, rekeyEpoch = rekeyEpoch)
        flow.value = contacts.values.toList()
    }

    override suspend fun updateIncomingStateAndEpochWithBitmap(
        id: String,
        counterIn: Int,
        chainKeyIn: EncryptedBlob,
        rekeyEpoch: Long,
        bitmapBase: Int,
        bitmap: ByteArray
    ) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(
            counterIn = counterIn,
            chainKeyIn = chainKeyIn,
            rekeyEpoch = rekeyEpoch,
            receivedBitmapBase = bitmapBase,
            receivedBitmap = bitmap
        )
        flow.value = contacts.values.toList()
    }

    override suspend fun updateRekeyEpoch(id: String, rekeyEpoch: Long) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(rekeyEpoch = rekeyEpoch)
        flow.value = contacts.values.toList()
    }

    override suspend fun updateVerifiedStatus(id: String, isVerified: Boolean) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(isVerified = isVerified)
        flow.value = contacts.values.toList()
    }

    override suspend fun updateContactName(id: String, name: EncryptedText) {
        val c = contacts[id] ?: return
        contacts[id] = c.copy(name = name)
        flow.value = contacts.values.toList()
    }

    override suspend fun deleteContact(id: String) {
        contacts.remove(id)
        flow.value = contacts.values.toList()
    }
}
