package org.pqchat.dht.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.db.MessageEntity
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.traffic.AdaptivePollingManager
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import java.util.UUID

class ChatViewModel(application: Application) : AndroidViewModel(application) {

    private val database = AppDatabase.getInstance(application)
    val dhtLeafNode = DhtLeafNode()
    val repository = ChatRepository(database, dhtLeafNode)

    val trafficGenerator = PoissonTrafficGenerator(dhtLeafNode)
    val pollingManager = AdaptivePollingManager { contactId ->
        if (contactId != null) {
            repository.pollContactIncoming(contactId)
        } else {
            val contacts = repository.contactDao.getAllContactsFlow().firstOrNull() ?: emptyList()
            for (c in contacts) {
                repository.pollContactIncoming(c.id)
            }
        }
    }

    val contacts: StateFlow<List<ContactEntity>> = repository.getAllContactsFlow()
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    private val _selectedContactId = MutableStateFlow<String?>(null)
    val selectedContactId: StateFlow<String?> = _selectedContactId.asStateFlow()

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val messages: StateFlow<List<MessageEntity>> = _selectedContactId
        .flatMapLatest { id ->
            if (id != null) repository.getMessagesFlow(id)
            else flowOf(emptyList())
        }
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    private val _dhtPeerCount = MutableStateFlow(0)
    val dhtPeerCount: StateFlow<Int> = _dhtPeerCount.asStateFlow()

    val pollingState = pollingManager.currentState

    private val _aliceHandshakeState = MutableStateFlow<HandshakeManager.AliceInitResult?>(null)
    val aliceHandshakeState: StateFlow<HandshakeManager.AliceInitResult?> = _aliceHandshakeState.asStateFlow()

    private val _isHandshaking = MutableStateFlow(false)
    val isHandshaking: StateFlow<Boolean> = _isHandshaking.asStateFlow()

    private val _statusNotification = MutableStateFlow<String?>(null)
    val statusNotification: StateFlow<String?> = _statusNotification.asStateFlow()

    val settingsManager = org.pqchat.dht.data.settings.AppSettingsManager(application)

    val themeMode: StateFlow<org.pqchat.dht.data.settings.ThemeMode> = settingsManager.themeMode
    val intervalForegroundChat: StateFlow<Long> = settingsManager.intervalForegroundChat
    val intervalAppActive: StateFlow<Long> = settingsManager.intervalAppActive
    val intervalBackgroundIdle: StateFlow<Long> = settingsManager.intervalBackgroundIdle
    val intervalDozeSleep: StateFlow<Long> = settingsManager.intervalDozeSleep

    init {
        dhtLeafNode.start()
        trafficGenerator.start()
        pollingManager.onAppForegrounded()
        syncPollingIntervals()

        // Ensure Self-Notes / DHT Loopback contact exists
        viewModelScope.launch {
            repository.ensureSelfNotesContactExists()
        }

        // Monitor DHT peers count
        viewModelScope.launch {
            while (true) {
                _dhtPeerCount.value = dhtLeafNode.getActivePeerCount()
                delay(2000L)
            }
        }
    }

    fun setThemeMode(mode: org.pqchat.dht.data.settings.ThemeMode) {
        settingsManager.setThemeMode(mode)
    }

    fun setIntervalForegroundChat(ms: Long) {
        settingsManager.setIntervalForegroundChat(ms)
        syncPollingIntervals()
    }

    fun setIntervalAppActive(ms: Long) {
        settingsManager.setIntervalAppActive(ms)
        syncPollingIntervals()
    }

    fun setIntervalBackgroundIdle(ms: Long) {
        settingsManager.setIntervalBackgroundIdle(ms)
        syncPollingIntervals()
    }

    fun setIntervalDozeSleep(ms: Long) {
        settingsManager.setIntervalDozeSleep(ms)
        syncPollingIntervals()
    }

    private fun syncPollingIntervals() {
        pollingManager.updateIntervals(
            foreground = settingsManager.intervalForegroundChat.value,
            appActive = settingsManager.intervalAppActive.value,
            bgIdle = settingsManager.intervalBackgroundIdle.value,
            doze = settingsManager.intervalDozeSleep.value
        )
    }

    fun openSelfNotes() {
        viewModelScope.launch {
            repository.ensureSelfNotesContactExists()
            _selectedContactId.value = ChatRepository.SELF_CONTACT_ID
            pollingManager.onChatOpened(ChatRepository.SELF_CONTACT_ID)
        }
    }

    fun selectContact(contactId: String) {
        _selectedContactId.value = contactId
        pollingManager.onChatOpened(contactId)
    }

    fun unselectContact() {
        _selectedContactId.value = null
        pollingManager.onChatClosed()
    }

    fun sendMessage(text: String) {
        val contactId = _selectedContactId.value ?: return
        if (text.isBlank()) return

        viewModelScope.launch {
            repository.sendTextMessage(contactId, text)
        }
    }

    fun sendTestPngImage() {
        val contactId = _selectedContactId.value ?: return

        viewModelScope.launch {
            val validPng: ByteArray = run {
                val bitmap = android.graphics.Bitmap.createBitmap(240, 240, android.graphics.Bitmap.Config.ARGB_8888)
                val canvas = android.graphics.Canvas(bitmap)
                val paint = android.graphics.Paint()
                paint.color = android.graphics.Color.rgb(0x00, 0xF5, 0xD4)
                canvas.drawRect(0f, 0f, 240f, 240f, paint)
                paint.color = android.graphics.Color.rgb(0x7B, 0x2C, 0xBF)
                canvas.drawCircle(120f, 120f, 80f, paint)
                paint.color = android.graphics.Color.rgb(0x00, 0xBB, 0xF9)
                canvas.drawCircle(120f, 120f, 40f, paint)
                val baos = java.io.ByteArrayOutputStream()
                bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, baos)
                baos.toByteArray()
            }

            val contact = repository.getContact(contactId) ?: return@launch
            val slot = org.pqchat.dht.protocol.RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            val chunks = ChunkingEngine.splitData(
                data = validPng,
                currentEdSeed = slot.edPrivateKeySeed,
                currentMsgKey = slot.msgKey,
                seqNum = contact.counterOut,
                ackNum = contact.counterIn
            )

            // Put chunks to DHT
            for (c in chunks) {
                dhtLeafNode.putMutable(
                    target = c.target,
                    v = c.frame1000,
                    seq = (c.chunkIndex + 1).toLong(),
                    sk = c.edPrivateKeySeed
                )
            }

            // Save outgoing message to DB
            repository.messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = "[PNG Image: ${validPng.size} bytes (${chunks.size} chunks)]",
                    imageBytes = validPng,
                    status = "SENT_DHT"
                )
            )

            repository.contactDao.updateOutgoingState(
                id = contactId,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )

            if (contactId == ChatRepository.SELF_CONTACT_ID) {
                repository.pollContactIncoming(contactId)
            }
        }
    }

    /**
     * Sends user-selected image file over DHT using 900-byte Chunking Engine.
     */
    fun sendImagePayload(rawBytes: ByteArray) {
        val contactId = _selectedContactId.value ?: return

        viewModelScope.launch(Dispatchers.IO) {
            val bitmap = android.graphics.BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.size)
            val finalBytes: ByteArray = if (bitmap != null) {
                val maxDim = 720
                val scaled = if (bitmap.width > maxDim || bitmap.height > maxDim) {
                    val ratio = minOf(maxDim.toFloat() / bitmap.width, maxDim.toFloat() / bitmap.height)
                    android.graphics.Bitmap.createScaledBitmap(
                        bitmap,
                        (bitmap.width * ratio).toInt(),
                        (bitmap.height * ratio).toInt(),
                        true
                    )
                } else {
                    bitmap
                }
                val baos = java.io.ByteArrayOutputStream()
                scaled.compress(android.graphics.Bitmap.CompressFormat.JPEG, 70, baos)
                baos.toByteArray()
            } else {
                rawBytes
            }

            val contact = repository.getContact(contactId) ?: return@launch
            val slot = org.pqchat.dht.protocol.RatchetChain.deriveSlot(contact.chainKeyOut, contact.counterOut)

            val chunks = ChunkingEngine.splitData(
                data = finalBytes,
                currentEdSeed = slot.edPrivateKeySeed,
                currentMsgKey = slot.msgKey,
                seqNum = contact.counterOut,
                ackNum = contact.counterIn
            )

            // Save outgoing message to DB immediately
            val msgId = repository.messageDao.insertMessage(
                MessageEntity(
                    contactId = contactId,
                    isOutgoing = true,
                    seqNum = contact.counterOut,
                    ackNum = contact.counterIn,
                    timestamp = System.currentTimeMillis(),
                    textContent = "[Image: ${finalBytes.size / 1024} KB (${chunks.size} chunks)]",
                    imageBytes = finalBytes,
                    status = "SENDING"
                )
            )

            repository.contactDao.updateOutgoingState(
                id = contactId,
                counterOut = contact.counterOut + 1,
                chainKeyOut = slot.nextChainKey
            )

            // Publish chunks to DHT
            for (c in chunks) {
                dhtLeafNode.putMutable(
                    target = c.target,
                    v = c.frame1000,
                    seq = (c.chunkIndex + 1).toLong(),
                    sk = c.edPrivateKeySeed
                )
            }

            repository.messageDao.updateStatus(msgId, "SENT_DHT")

            if (contactId == ChatRepository.SELF_CONTACT_ID) {
                repository.pollContactIncoming(contactId)
            }
        }
    }

    /**
     * Alice initiates Handshake:
     * Generates QR code data, begins polling Target_0 on DHT.
     */
    fun startAliceHandshake(contactName: String = "Bob") {
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        _aliceHandshakeState.value = aliceInit
        _isHandshaking.value = true

        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Waiting for partner to scan QR and PUT to DHT..."
            var attempts = 0
            while (_isHandshaking.value && attempts < 60) {
                delay(3000L)
                attempts++
                val item = dhtLeafNode.getMutable(aliceInit.target0)
                if (item != null) {
                    try {
                        val session = HandshakeManager.aliceFinalize(
                            skA = aliceInit.skA,
                            seedInit = aliceInit.seedInit,
                            frame1000 = item.v
                        )

                        val newContactId = UUID.randomUUID().toString()
                        val newContact = ContactEntity(
                            id = newContactId,
                            name = contactName,
                            chainKeyOut = session.chainKeyOut,
                            chainKeyIn = session.chainKeyIn,
                            counterOut = session.counterOut,
                            counterIn = session.counterIn
                        )

                        repository.addContact(newContact)
                        _aliceHandshakeState.value = null
                        _isHandshaking.value = false
                        _selectedContactId.value = newContactId
                        _statusNotification.value = "Handshake complete! Post-quantum tunnel established."
                        break
                    } catch (_: Exception) {}
                }
            }
            if (_isHandshaking.value) {
                _statusNotification.value = "Handshake timed out. Try again."
                _isHandshaking.value = false
            }
        }
    }

    /**
     * Bob joins Handshake:
     * Scans QR bytes, encapsulates ML-KEM-512 secret, puts to DHT at Target_0.
     */
    fun processBobHandshake(qrBytes: ByteArray, contactName: String = "Alice") {
        viewModelScope.launch(Dispatchers.IO) {
            _isHandshaking.value = true
            _statusNotification.value = "Encapsulating Post-Quantum secret and sending to DHT..."

            try {
                val bobResult = HandshakeManager.bobProcessQr(qrBytes)

                // PUT to DHT Target_0
                val putSuccess = dhtLeafNode.putMutable(
                    target = bobResult.target0,
                    v = bobResult.frame1000,
                    seq = 1L,
                    salt = null,
                    sk = bobResult.edPrivateKeySeed
                )

                val newContactId = UUID.randomUUID().toString()
                val newContact = ContactEntity(
                    id = newContactId,
                    name = contactName,
                    chainKeyOut = bobResult.chainKeyBtoA,
                    chainKeyIn = bobResult.chainKeyAtoB,
                    counterOut = 0,
                    counterIn = 0
                )

                repository.addContact(newContact)
                _isHandshaking.value = false
                _selectedContactId.value = newContactId
                _statusNotification.value = "Connected! Post-quantum ratcheting active."
            } catch (e: Exception) {
                _statusNotification.value = "Failed to process QR: ${e.message}"
                _isHandshaking.value = false
            }
        }
    }

    fun dismissNotification() {
        _statusNotification.value = null
    }

    override fun onCleared() {
        super.onCleared()
        dhtLeafNode.stop()
        trafficGenerator.stop()
        pollingManager.stop()
    }
}
