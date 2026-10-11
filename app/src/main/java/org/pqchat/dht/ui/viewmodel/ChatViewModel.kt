package org.pqchat.dht.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.pqchat.dht.crypto.CryptoUtils
import org.pqchat.dht.data.db.AppDatabase
import org.pqchat.dht.data.db.ContactEntity
import org.pqchat.dht.data.db.MessageEntity
import org.pqchat.dht.data.repository.ChatRepository
import org.pqchat.dht.dht.leaf.DhtClient
import org.pqchat.dht.dht.leaf.DhtLeafNode
import org.pqchat.dht.protocol.ChunkingEngine
import org.pqchat.dht.protocol.HandshakeManager
import org.pqchat.dht.traffic.AdaptivePollingManager
import org.pqchat.dht.traffic.PoissonTrafficGenerator
import java.util.UUID

class ChatViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as? org.pqchat.dht.PQChatApplication
    private val database = app?.database ?: AppDatabase.getInstance(application)
    val dhtLeafNode = app?.dhtLeafNode ?: DhtLeafNode(nodeCacheDao = database.dhtNodeCacheDao())
    val repository = app?.repository ?: ChatRepository(database, dhtLeafNode)

    val settingsManager = app?.settingsManager ?: org.pqchat.dht.data.settings.AppSettingsManager(application)
    val trafficGenerator = app?.trafficGenerator ?: PoissonTrafficGenerator(
        dhtLeafNode,
        blindRepublishPool = repository.blindRepublishPool,
        crowdsourcedRepublishEnabledProvider = { settingsManager.isCrowdsourcedRepublishEnabled.value }
    )
    val pollingScheduler = app?.pollingScheduler ?: org.pqchat.dht.service.PollingScheduler(
        application,
        repository,
        dhtLeafNode,
        settingsManager
    )
    val pollingManager = pollingScheduler.pollingManager

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
    val nextPollInMs = pollingManager.nextPollInMs
    val isSyncing = pollingManager.isSyncing

    val isForegroundServiceEnabled = settingsManager.isForegroundServiceEnabled

    private val _aliceHandshakeState = MutableStateFlow<HandshakeManager.AliceInitResult?>(null)
    val aliceHandshakeState: StateFlow<HandshakeManager.AliceInitResult?> = _aliceHandshakeState.asStateFlow()

    data class HandshakeCompletedState(
        val contactId: String,
        val contactName: String,
        val sas: String
    )

    private val _handshakeCompleted = MutableStateFlow<HandshakeCompletedState?>(null)
    val handshakeCompleted: StateFlow<HandshakeCompletedState?> = _handshakeCompleted.asStateFlow()

    private val _isHandshaking = MutableStateFlow(false)
    val isHandshaking: StateFlow<Boolean> = _isHandshaking.asStateFlow()

    private val _statusNotification = MutableStateFlow<String?>(null)
    val statusNotification: StateFlow<String?> = _statusNotification.asStateFlow()

    val themeMode: StateFlow<org.pqchat.dht.data.settings.ThemeMode> = settingsManager.themeMode
    val intervalForegroundChat: StateFlow<Long> = settingsManager.intervalForegroundChat
    val intervalAppActive: StateFlow<Long> = settingsManager.intervalAppActive
    val intervalBackgroundIdle: StateFlow<Long> = settingsManager.intervalBackgroundIdle
    val intervalDozeSleep: StateFlow<Long> = settingsManager.intervalDozeSleep

    val intervalRepublishTier1: StateFlow<Long> = settingsManager.intervalRepublishTier1
    val intervalRepublishTier2: StateFlow<Long> = settingsManager.intervalRepublishTier2
    val intervalRepublishTier3: StateFlow<Long> = settingsManager.intervalRepublishTier3
    val republishMaxTtl: StateFlow<Long> = settingsManager.republishMaxTtl

    val imageMaxEdge: StateFlow<Int> = settingsManager.imageMaxEdge
    val imageColorCount: StateFlow<Int> = settingsManager.imageColorCount

    val isCrowdsourcedRepublishEnabled: StateFlow<Boolean> = settingsManager.isCrowdsourcedRepublishEnabled

    init {
        if (app == null) {
            dhtLeafNode.start()
            trafficGenerator.start()
        }
        pollingScheduler.start()
        pollingScheduler.onAppForegrounded()

        // Ensure Self-Notes / DHT Loopback contact exists and pre-warm targets
        viewModelScope.launch {
            repository.ensureSelfNotesContactExists()
            repository.preWarmAllContactsNextTargets()
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

    fun setIntervalRepublishTier1(ms: Long) {
        settingsManager.setIntervalRepublishTier1(ms)
    }

    fun setIntervalRepublishTier2(ms: Long) {
        settingsManager.setIntervalRepublishTier2(ms)
    }

    fun setIntervalRepublishTier3(ms: Long) {
        settingsManager.setIntervalRepublishTier3(ms)
    }

    fun setRepublishMaxTtl(ms: Long) {
        settingsManager.setRepublishMaxTtl(ms)
    }

    fun setImageMaxEdge(maxEdge: Int) {
        settingsManager.setImageMaxEdge(maxEdge)
    }

    fun setImageColorCount(colors: Int) {
        settingsManager.setImageColorCount(colors)
    }

    fun setCrowdsourcedRepublishEnabled(enabled: Boolean) {
        settingsManager.setCrowdsourcedRepublishEnabled(enabled)
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

    /** Trigger an immediate DHT poll (ignores current countdown). */
    fun triggerImmediatePoll() {
        pollingManager.triggerImmediatePoll()
    }

    fun sendMessage(text: String) {
        val contactId = _selectedContactId.value ?: return
        if (text.isBlank()) return

        viewModelScope.launch {
            repository.sendTextMessage(contactId, text)
        }
    }

    /**
     * Compresses user-selected image file into PNG8 format (with maxEdge and colorCount settings)
     * and sends it over DHT using the 800-byte Chunking Engine.
     */
    fun sendImagePayload(rawBytes: ByteArray) {
        val contactId = _selectedContactId.value ?: return
        val maxEdge = settingsManager.imageMaxEdge.value
        val colorCount = settingsManager.imageColorCount.value

        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Kompresowanie obrazu (PNG8)..."
            val finalBytes = org.pqchat.dht.media.Png8Compressor.compressToPng8(rawBytes, maxEdge, colorCount)
            _statusNotification.value = "Wysyłanie obrazu (${finalBytes.size} B) przez DHT..."
            val success = repository.sendImagePayload(contactId, finalBytes)
            if (success) {
                _statusNotification.value = "Wysłano obraz (${finalBytes.size} B) przez DHT"
            } else {
                _statusNotification.value = "Błąd wysyłania obrazu"
            }
        }
    }

    /**
     * Alice initiates Handshake:
     * Generates QR code data, begins polling Target_0 on DHT.
     */
    private var bobRepublishJob: Job? = null

    /**
     * Alice initiates Handshake:
     * Generates QR code data, begins polling Target_0 on DHT with an extended window (10 minutes).
     * Sensitive private key sk_A is preserved across corrupted/invalid frames and only wiped on verified key confirmation.
     */
    fun startAliceHandshake(contactName: String = "Bob") {
        val aliceInit = HandshakeManager.aliceCreateHandshake()
        _aliceHandshakeState.value = aliceInit
        _isHandshaking.value = true
        dhtLeafNode.preWarmTargetAsync(aliceInit.target0)

        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Waiting for partner to scan QR and PUT to DHT..."
            var attempts = 0
            val maxAttempts = 200 // 200 * 3000ms = 600s = 10 minutes
            while (_isHandshaking.value && attempts < maxAttempts) {
                delay(3000L)
                attempts++
                if (attempts % 4 == 0) {
                    dhtLeafNode.targetRouteCache.remove(aliceInit.target0)
                }
                val item = dhtLeafNode.getMutable(aliceInit.target0)
                if (item != null) {
                    try {
                        val session = HandshakeManager.aliceFinalize(
                            skA = aliceInit.skA,
                            pkA = aliceInit.pkA,
                            seedInit = aliceInit.seedInit,
                            frame = item.v
                        )

                        org.pqchat.dht.debug.MessageDebugLogger.logIncomingAliceHandshakeFinalize(
                            target = aliceInit.target0,
                            seq = item.seq,
                            senderEdPublicKey = item.k,
                            senderSignature = item.sig,
                            frame = item.v,
                            seedInit = aliceInit.seedInit,
                            decapsulationSuccess = true
                        )

                        val newContactId = UUID.randomUUID().toString()
                        val newContact = ContactEntity(
                            id = newContactId,
                            name = contactName,
                            chainKeyOut = session.chainKeyOut,
                            chainKeyIn = session.chainKeyIn,
                            counterOut = session.counterOut,
                            counterIn = session.counterIn,
                            isInitiator = true,
                            sas = session.sas,
                            fingerprint = session.fingerprint
                        )

                        repository.addContact(newContact)
                        _aliceHandshakeState.value = null
                        _isHandshaking.value = false
                        _handshakeCompleted.value = HandshakeCompletedState(
                            contactId = newContactId,
                            contactName = contactName,
                            sas = session.sas
                        )
                        _statusNotification.value = "Connected! SAS: ${session.sas}. Post-quantum ratcheting active."
                        break
                    } catch (_: Exception) {
                        // Key confirmation failed or frame corrupted: preserve skA and keep listening
                    }
                }
            }
            if (_isHandshaking.value) {
                _statusNotification.value = "Handshake timed out (10 min). Try again."
                aliceInit.destroySensitiveKeys()
                _aliceHandshakeState.value = null
                _isHandshaking.value = false
            }
        }
    }

    /**
     * Bob joins Handshake:
     * Scans QR bytes, encapsulates ML-KEM-512 secret, checks putMutable result,
     * and sets up periodic republish to DHT at Target_0.
     */
    fun processBobHandshake(qrBytes: ByteArray, contactName: String = "Alice") {
        viewModelScope.launch(Dispatchers.IO) {
            _isHandshaking.value = true
            _statusNotification.value = "Encapsulating Post-Quantum secret and sending to DHT..."

            try {
                val bobResult = HandshakeManager.bobProcessQr(qrBytes)
                dhtLeafNode.preWarmTarget(bobResult.target0)

                org.pqchat.dht.debug.MessageDebugLogger.logOutgoingBobHandshake(
                    target = bobResult.target0,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    edPrivateKeySeed = bobResult.edPrivateKeySeed,
                    frame = bobResult.frame
                )

                // 1. Bob verifies the result of putMutable
                val success = dhtLeafNode.putMutable(
                    target = bobResult.target0,
                    v = bobResult.frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = bobResult.edPrivateKeySeed
                )

                if (!success) {
                    _statusNotification.value = "Initial DHT publish failed, retrying in background..."
                }

                // 2. Launch republish loop: periodically republish to Target_0
                bobRepublishJob?.cancel()
                bobRepublishJob = viewModelScope.launch(Dispatchers.IO) {
                    var republishCount = 0
                    // Republish every 15s for up to 10 minutes (40 iterations)
                    while (isActive && republishCount < 40) {
                        delay(15_000L)
                        republishCount++
                        dhtLeafNode.putMutable(
                            target = bobResult.target0,
                            v = bobResult.frame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            salt = null,
                            sk = bobResult.edPrivateKeySeed
                        )
                    }
                }

                val newContactId = UUID.randomUUID().toString()
                val newContact = ContactEntity(
                    id = newContactId,
                    name = contactName,
                    chainKeyOut = bobResult.chainKeyBtoA,
                    chainKeyIn = bobResult.chainKeyAtoB,
                    counterOut = 0,
                    counterIn = 0,
                    isInitiator = false,
                    sas = bobResult.sas,
                    fingerprint = bobResult.fingerprint
                )

                repository.addContact(newContact)
                _isHandshaking.value = false
                _handshakeCompleted.value = HandshakeCompletedState(
                    contactId = newContactId,
                    contactName = contactName,
                    sas = bobResult.sas
                )
                _statusNotification.value = "Connected! SAS: ${bobResult.sas}. Post-quantum ratcheting active."
            } catch (e: Exception) {
                _statusNotification.value = "Failed to process QR: ${e.message}"
                _isHandshaking.value = false
            }
        }
    }

    fun setForegroundServiceEnabled(enabled: Boolean) {
        pollingScheduler.setForegroundServiceEnabled(enabled)
    }

    fun setContactVerified(contactId: String, isVerified: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setContactVerified(contactId, isVerified)
        }
    }

    fun toggleContactVerified(contactId: String, currentVerified: Boolean) {
        setContactVerified(contactId, !currentVerified)
    }

    fun updateContactName(contactId: String, newName: String) {
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            repository.updateContactName(contactId, trimmed)
        }
    }

    fun confirmHandshakeAndVerify(contactId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setContactVerified(contactId, true)
        }
        _selectedContactId.value = contactId
        resetHandshakeState()
    }

    fun confirmHandshakeWithoutVerification(contactId: String) {
        _selectedContactId.value = contactId
        resetHandshakeState()
    }

    fun resetHandshakeState() {
        _aliceHandshakeState.value?.destroySensitiveKeys()
        _aliceHandshakeState.value = null
        _isHandshaking.value = false
        _handshakeCompleted.value = null
        _statusNotification.value = null
    }

    fun dismissNotification() {
        _statusNotification.value = null
    }

    override fun onCleared() {
        super.onCleared()
        bobRepublishJob?.cancel()
        resetHandshakeState()
        if (app == null) {
            dhtLeafNode.stop()
            trafficGenerator.stop()
            pollingScheduler.stop()
        }
    }
}
