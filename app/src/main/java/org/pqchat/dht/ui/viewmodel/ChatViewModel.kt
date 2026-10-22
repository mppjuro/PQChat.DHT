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
import org.pqchat.dht.data.db.GroupEntity
import org.pqchat.dht.data.db.GroupMemberEntity
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
    val settingsManager = app?.settingsManager ?: org.pqchat.dht.data.settings.AppSettingsManager(application)
    val repository = app?.repository ?: ChatRepository(database, dhtLeafNode, settingsManager = settingsManager)
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

    val resourceProfiler: org.pqchat.dht.debug.AndroidResourceProfiler =
        app?.resourceProfiler ?: org.pqchat.dht.debug.AndroidResourceProfiler(
            context = application,
            dhtClient = dhtLeafNode,
            pollingManager = pollingManager,
            trafficGenerator = trafficGenerator
        )

    val isProfiling: StateFlow<Boolean> = resourceProfiler.isProfiling
    val profileSampleCount: StateFlow<Int> = resourceProfiler.sampleCount
    val latestResourceSample: StateFlow<org.pqchat.dht.debug.AndroidResourceProfiler.ResourceSample?> = resourceProfiler.latestSample

    fun startProfilingSession(label: String) {
        resourceProfiler.startSession(label)
    }

    fun stopProfilingSession() {
        resourceProfiler.stopSession()
    }

    fun clearProfilingSamples() {
        resourceProfiler.clearSamples()
    }

    fun exportProfilingCsvFile(): java.io.File {
        return resourceProfiler.exportToCsvFile()
    }

    val contacts: StateFlow<List<ContactEntity>> = repository.getAllContactsFlow()
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    val groups: StateFlow<List<GroupEntity>> = repository.getAllGroupsFlow()
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    fun getGroupMembersFlow(groupId: String): Flow<List<GroupMemberEntity>> =
        repository.getGroupMembersFlow(groupId)

    private val _selectedContactId = MutableStateFlow<String?>(null)
    val selectedContactId: StateFlow<String?> = _selectedContactId.asStateFlow()

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val messages: StateFlow<List<MessageEntity>> = _selectedContactId
        .flatMapLatest { id ->
            if (id != null) repository.getMessagesFlow(id)
            else flowOf(emptyList())
        }
        .stateIn(viewModelScope, SharingStarted.Lazily, emptyList())

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val isRekeyInProgress: StateFlow<Boolean> = _selectedContactId
        .flatMapLatest { id ->
            if (id != null) repository.isRekeyPendingFlow(id)
            else flowOf(false)
        }
        .stateIn(viewModelScope, SharingStarted.Lazily, false)

    val imageDownloadProgress: StateFlow<Map<String, ChatRepository.ImageDownloadProgress>> = repository.imageDownloadProgress

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val currentContactDownloadProgress: StateFlow<List<ChatRepository.ImageDownloadProgress>> = _selectedContactId
        .flatMapLatest { contactId ->
            if (contactId == null) flowOf(emptyList())
            else repository.imageDownloadProgress.map { map ->
                map.values.filter { it.contactId == contactId }
            }
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
    val isTorEnabled: StateFlow<Boolean> = settingsManager.isTorEnabled
    val isBiometricLockEnabled: StateFlow<Boolean> = settingsManager.isBiometricLockEnabled
    val isAppLockPinSet: StateFlow<Boolean> = settingsManager.isAppLockPinSet
    val isDuressPinSet: StateFlow<Boolean> = settingsManager.isDuressPinSet
    val isDuressActive: StateFlow<Boolean> = settingsManager.isDuressActive
    val isStrictPoissonShapingEnabled: StateFlow<Boolean> = settingsManager.isStrictPoissonShapingEnabled
    val torState: StateFlow<org.pqchat.dht.network.tor.TorState> =
        app?.embeddedTorManager?.state ?: MutableStateFlow(org.pqchat.dht.network.tor.TorState.Disconnected)

    fun setTorEnabled(enabled: Boolean) {
        settingsManager.setTorEnabled(enabled)
    }

    fun setBiometricLockEnabled(enabled: Boolean) {
        settingsManager.setBiometricLockEnabled(enabled)
    }

    fun setAppLockPin(pin: String?) {
        settingsManager.setAppLockPin(pin)
    }

    fun setDuressPin(pin: String?) {
        settingsManager.setDuressPin(pin)
    }

    fun verifyPin(pin: String): org.pqchat.dht.data.settings.PinAuthResult {
        return settingsManager.verifyPin(pin)
    }

    fun triggerDuressMode() {
        runCatching {
            kotlinx.coroutines.runBlocking(Dispatchers.IO) {
                kotlinx.coroutines.withTimeoutOrNull(2000L) {
                    repository.triggerSafetyCanary(org.pqchat.dht.crypto.BinaryFrameCodec.CANARY_REASON_DURESS_PIN)
                }
            }
        }
        org.pqchat.dht.crypto.KeystoreCrypto.deleteMasterKey()
        settingsManager.setDuressActive(true)
    }

    fun clearDuressActive() {
        settingsManager.clearDuressActive()
    }

    fun setStrictPoissonShapingEnabled(enabled: Boolean) {
        settingsManager.setStrictPoissonShapingEnabled(enabled)
    }

    // Safety Canary / Dead Man's Switch
    val isDeadManSwitchEnabled: StateFlow<Boolean> = settingsManager.isDeadManSwitchEnabled
    val deadManSwitchTimeoutHours: StateFlow<Int> = settingsManager.deadManSwitchTimeoutHours
    val deadManTrustedContactIds: StateFlow<Set<String>> = settingsManager.deadManTrustedContactIds
    val deadManEmergencyNote: StateFlow<String> = settingsManager.deadManEmergencyNote
    val lastUserActivityTimestamp: StateFlow<Long> = settingsManager.lastUserActivityTimestamp
    val isCanaryTriggered: StateFlow<Boolean> = settingsManager.isCanaryTriggered

    fun setDeadManSwitchEnabled(enabled: Boolean) {
        settingsManager.setDeadManSwitchEnabled(enabled)
    }

    fun setDeadManSwitchTimeoutHours(hours: Int) {
        settingsManager.setDeadManSwitchTimeoutHours(hours)
    }

    fun toggleDeadManTrustedContact(contactId: String) {
        val current = settingsManager.deadManTrustedContactIds.value
        if (current.contains(contactId)) {
            settingsManager.removeDeadManTrustedContactId(contactId)
        } else {
            settingsManager.addDeadManTrustedContactId(contactId)
        }
    }

    fun setDeadManEmergencyNote(note: String) {
        settingsManager.setDeadManEmergencyNote(note)
    }

    fun recordUserActivity() {
        settingsManager.recordUserActivity()
    }

    fun resetCanaryTriggered() {
        settingsManager.setCanaryTriggered(false)
    }

    fun triggerManualSos(latitude: Double = 0.0, longitude: Double = 0.0, note: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
            val queued = repository.triggerSafetyCanary(
                triggerReason = org.pqchat.dht.crypto.BinaryFrameCodec.CANARY_REASON_MANUAL_SOS,
                latitude = latitude,
                longitude = longitude,
                customNote = note
            )
            settingsManager.setCanaryTriggered(true)
            if (queued > 0) {
                _statusNotification.value = "Emergency SOS canary queued ($queued contacts)"
            } else {
                _statusNotification.value = "No contacts available for SOS"
            }
        }
    }

    // Master's Thesis Research Telemetry & Firebase Sync
    val isAnonymousStatsEnabled: StateFlow<Boolean> = settingsManager.isAnonymousStatsEnabled
    val statsProbeIntervalMs: StateFlow<Long> = settingsManager.statsProbeIntervalMs

    val researchTelemetry: org.pqchat.dht.research.ResearchTelemetryManager?
        get() = app?.researchTelemetryManager

    val researchEventsCount: StateFlow<Int> = researchTelemetry?.eventsCount ?: MutableStateFlow(0)
    val researchFirstSendCount: StateFlow<Int> = researchTelemetry?.firstSendCount ?: MutableStateFlow(0)
    val researchOwnRepublishCount: StateFlow<Int> = researchTelemetry?.ownRepublishCount ?: MutableStateFlow(0)
    val researchCrowdRepublishCount: StateFlow<Int> = researchTelemetry?.crowdRepublishCount ?: MutableStateFlow(0)
    val researchPacketsReceivedCount: StateFlow<Int> = researchTelemetry?.packetsReceivedCount ?: MutableStateFlow(0)
    val researchTtlSamplesCount: StateFlow<Int> = researchTelemetry?.ttlSamplesCount ?: MutableStateFlow(0)
    val researchSyncStatus: StateFlow<String> = researchTelemetry?.syncStatus ?: MutableStateFlow("Disabled")

    fun setAnonymousStatsEnabled(enabled: Boolean) {
        settingsManager.setAnonymousStatsEnabled(enabled)
    }

    fun setStatsProbeIntervalMs(millis: Long) {
        settingsManager.setStatsProbeIntervalMs(millis)
    }

    fun triggerFirebaseSyncNow() {
        viewModelScope.launch {
            researchTelemetry?.forceFirebaseSync()
        }
    }

    fun getShareCsvIntent(context: android.content.Context): android.content.Intent? {
        return researchTelemetry?.createShareCsvIntent(context)
    }

    fun getShareZipIntent(context: android.content.Context): android.content.Intent? {
        return researchTelemetry?.createShareZipIntent(context)
    }

    init {
        repository.settingsManager = settingsManager
        trafficGenerator.safetyCanaryProvider = { repository.pollPendingSafetyCanary() }
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

        // Periodic purge of expired ephemeral messages
        viewModelScope.launch {
            while (isActive) {
                try {
                    repository.purgeExpiredMessages()
                } catch (_: Throwable) {}
                delay(1000L)
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

    private val _ephemeralTtlSeconds = MutableStateFlow(0L)
    val ephemeralTtlSeconds: StateFlow<Long> = _ephemeralTtlSeconds.asStateFlow()

    fun setEphemeralTtl(seconds: Long) {
        _ephemeralTtlSeconds.value = seconds
    }

    fun selectContact(contactId: String) {
        _selectedContactId.value = contactId
        pollingManager.onChatOpened(contactId)
        viewModelScope.launch {
            repository.markIncomingMessagesAsRead(contactId)
            repository.pollConstantBatch(contactId)
        }
    }

    fun unselectContact() {
        _selectedContactId.value = null
        pollingManager.onChatClosed()
    }

    fun createGroup(groupName: String, contactIds: List<String>) {
        if (groupName.isBlank()) return
        viewModelScope.launch {
            val group = repository.createGroup(groupName, contactIds)
            selectContact(group.groupId)
        }
    }

    fun leaveGroup(groupId: String) {
        viewModelScope.launch {
            repository.leaveGroup(groupId)
            if (_selectedContactId.value == groupId) {
                unselectContact()
            }
        }
    }

    /** Trigger an immediate DHT poll (ignores current countdown). */
    fun triggerImmediatePoll() {
        pollingManager.triggerImmediatePoll()
    }

    fun sendMessage(text: String) {
        val contactId = _selectedContactId.value ?: return
        if (text.isBlank()) return

        val ttl = _ephemeralTtlSeconds.value
        viewModelScope.launch {
            val group = repository.getGroup(contactId)
            if (group != null) {
                repository.sendGroupMessage(contactId, text, ttl)
            } else {
                repository.sendTextMessage(contactId, text, ttl)
            }
        }
    }

    fun sendReaction(targetMessage: MessageEntity, emoji: String) {
        val contactId = _selectedContactId.value ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val group = repository.getGroup(contactId)
            val success = if (group != null) {
                repository.sendGroupReaction(contactId, targetMessage, emoji)
            } else {
                repository.sendReaction(contactId, targetMessage, emoji)
            }
            if (!success) {
                _statusNotification.value = "Failed to send reaction to DHT"
            }
        }
    }

    fun sendLocationPin(
        latitude: Double,
        longitude: Double,
        altitude: Double = 0.0,
        accuracy: Float = 0.0f,
        note: String = ""
    ) {
        val contactId = _selectedContactId.value ?: return
        val ttl = _ephemeralTtlSeconds.value
        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Sending location pin via DHT..."
            val group = repository.getGroup(contactId)
            val success = if (group != null) {
                repository.sendGroupLocationPin(contactId, latitude, longitude, altitude, accuracy, note, ttl)
            } else {
                repository.sendLocationPin(contactId, latitude, longitude, altitude, accuracy, note, ttl)
            }
            if (success) {
                _statusNotification.value = "Location pin sent"
            } else {
                _statusNotification.value = "Error sending location pin"
            }
        }
    }

    fun resendMessage(messageId: Long) {
        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Resending message..."
            val success = repository.resendMessage(messageId)
            if (success) {
                _statusNotification.value = "Message sent successfully"
            } else {
                _statusNotification.value = "Failed to send message to DHT"
            }
        }
    }

    fun getPollFlow(pollId: String): Flow<org.pqchat.dht.data.db.PollEntity?> =
        repository.getPollFlow(pollId)

    fun getPollVotesFlow(pollId: String): Flow<List<org.pqchat.dht.data.db.PollVoteEntity>> =
        repository.getPollVotesFlow(pollId)

    fun getPollsForGroupFlow(groupId: String): Flow<List<org.pqchat.dht.data.db.PollEntity>> =
        repository.getPollsForGroupFlow(groupId)

    fun createGroupPoll(
        groupId: String,
        question: String,
        options: List<String>,
        isMultiChoice: Boolean,
        durationHours: Int = 24
    ) {
        if (question.isBlank() || options.size < 2) return
        viewModelScope.launch(Dispatchers.IO) {
            val pollId = repository.createGroupPoll(
                groupId = groupId,
                question = question.trim(),
                options = options.map { it.trim() },
                isMultiChoice = isMultiChoice,
                durationHours = durationHours
            )
            if (pollId != null) {
                _statusNotification.value = "Group poll created"
            } else {
                _statusNotification.value = "Failed to create group poll"
            }
        }
    }

    fun voteGroupPoll(
        groupId: String,
        pollId: String,
        selectedBitmask: Int
    ) {
        if (selectedBitmask <= 0) return
        viewModelScope.launch(Dispatchers.IO) {
            val success = repository.voteGroupPoll(
                groupId = groupId,
                pollId = pollId,
                selectedBitmask = selectedBitmask
            )
            if (success) {
                _statusNotification.value = "Vote submitted"
            } else {
                _statusNotification.value = "Failed to submit vote"
            }
        }
    }

    fun initiateRekey() {
        val contactId = _selectedContactId.value ?: return
        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Initiating ML-KEM key exchange..."
            val success = repository.initiateRekey(contactId)
            if (success) {
                _statusNotification.value = "Sent ML-KEM key exchange offer (Type 0x03)"
            }
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
            _statusNotification.value = "Compressing image (PNG8)..."
            val finalBytes = org.pqchat.dht.media.Png8Compressor.compressToPng8(rawBytes, maxEdge, colorCount)
            _statusNotification.value = "Sending image (${finalBytes.size} B) via DHT..."
            val success = repository.sendImagePayload(contactId, finalBytes)
            if (success) {
                _statusNotification.value = "Image (${finalBytes.size} B) sent via DHT"
            } else {
                _statusNotification.value = "Error sending image"
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
                    frame = bobResult.frame
                )

                // 1. Bob verifies the result of putMutable
                val tStart = System.currentTimeMillis()
                val success = dhtLeafNode.putMutable(
                    target = bobResult.target0,
                    v = bobResult.frame,
                    seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                    salt = null,
                    sk = bobResult.edPrivateKeySeed
                )
                val rttMs = System.currentTimeMillis() - tStart
                researchTelemetry?.recordPacketEvent(
                    role = org.pqchat.dht.research.PacketRole.FIRST_SEND,
                    target = bobResult.target0,
                    seqNum = 0L,
                    payloadBytes = bobResult.frame.size,
                    rttMs = rttMs,
                    nodesQueried = dhtLeafNode.lastNodesQueried,
                    nodesResponded = dhtLeafNode.lastNodesResponded,
                    lookupHops = dhtLeafNode.lastLookupHops,
                    success = success,
                    republishAttempt = 0
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
                        val tRepubStart = System.currentTimeMillis()
                        val repOk = dhtLeafNode.putMutable(
                            target = bobResult.target0,
                            v = bobResult.frame,
                            seq = DhtClient.DEFAULT_MUTABLE_SEQ,
                            salt = null,
                            sk = bobResult.edPrivateKeySeed
                        )
                        val repRtt = System.currentTimeMillis() - tRepubStart
                        researchTelemetry?.recordPacketEvent(
                            role = org.pqchat.dht.research.PacketRole.OWN_REPUBLISH,
                            target = bobResult.target0,
                            seqNum = 0L,
                            payloadBytes = bobResult.frame.size,
                            rttMs = repRtt,
                            nodesQueried = dhtLeafNode.lastNodesQueried,
                            nodesResponded = dhtLeafNode.lastNodesResponded,
                            lookupHops = dhtLeafNode.lastLookupHops,
                            success = repOk,
                            republishAttempt = republishCount
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

    val voiceRecorder = org.pqchat.dht.media.voice.VoiceRecorder(viewModelScope)
    val voicePlayer = org.pqchat.dht.media.voice.VoicePlayer(viewModelScope)

    private val _isRecordingVoice = MutableStateFlow(false)
    val isRecordingVoice: StateFlow<Boolean> = _isRecordingVoice.asStateFlow()

    private val _recordingAmplitude = MutableStateFlow(0f)
    val recordingAmplitude: StateFlow<Float> = _recordingAmplitude.asStateFlow()

    private val _recordingDurationMs = MutableStateFlow(0)
    val recordingDurationMs: StateFlow<Int> = _recordingDurationMs.asStateFlow()

    private val _recordingBytesCount = MutableStateFlow(0)
    val recordingBytesCount: StateFlow<Int> = _recordingBytesCount.asStateFlow()

    private val _recordingFramesCount = MutableStateFlow(1)
    val recordingFramesCount: StateFlow<Int> = _recordingFramesCount.asStateFlow()

    private val _voiceMaxFrames = MutableStateFlow(3)
    val voiceMaxFrames: StateFlow<Int> = _voiceMaxFrames.asStateFlow()

    private val _playingMessageId = MutableStateFlow<Long?>(null)
    val playingMessageId: StateFlow<Long?> = _playingMessageId.asStateFlow()

    private val _playbackProgress = MutableStateFlow(0f)
    val playbackProgress: StateFlow<Float> = _playbackProgress.asStateFlow()

    fun setVoiceMaxFrames(maxFrames: Int) {
        _voiceMaxFrames.value = maxFrames.coerceIn(1, 3)
    }

    fun startVoiceRecording(maxFrames: Int = _voiceMaxFrames.value): Boolean {
        if (_isRecordingVoice.value) return false
        _recordingDurationMs.value = 0
        _recordingBytesCount.value = 0
        _recordingFramesCount.value = 1
        _recordingAmplitude.value = 0f

        val started = voiceRecorder.startRecording(
            maxFrames = maxFrames,
            onAmplitude = { amp ->
                _recordingAmplitude.value = amp
            },
            onProgress = { dur, bytes, frames ->
                _recordingDurationMs.value = dur
                _recordingBytesCount.value = bytes
                _recordingFramesCount.value = frames
            },
            onAutoStop = {
                stopAndSendVoiceRecording(cancel = false)
            }
        )

        if (started) {
            _isRecordingVoice.value = true
        }
        return started
    }

    fun stopAndSendVoiceRecording(cancel: Boolean = false) {
        if (!_isRecordingVoice.value) return
        _isRecordingVoice.value = false
        _recordingAmplitude.value = 0f

        if (cancel) {
            voiceRecorder.cancel()
            _statusNotification.value = "Voice note discarded"
            return
        }

        val result = voiceRecorder.stop()
        if (result == null || result.pcm16Samples.isEmpty()) {
            _statusNotification.value = "No audio recorded"
            return
        }

        val contactId = _selectedContactId.value ?: return
        val ttl = _ephemeralTtlSeconds.value

        viewModelScope.launch(Dispatchers.IO) {
            _statusNotification.value = "Compressing voice note (LPC-10 / 1280 bps)..."
            val voiceBytes = org.pqchat.dht.media.voice.VoiceCodec.encode(result.pcm16Samples)
            val frames = ((voiceBytes.size + org.pqchat.dht.crypto.BinaryFrameCodec.T9_MAX_VOICE_SIZE - 1) / org.pqchat.dht.crypto.BinaryFrameCodec.T9_MAX_VOICE_SIZE).coerceIn(1, 3)
            _statusNotification.value = "Sending PTT voice note (${voiceBytes.size} B • $frames frame${if (frames > 1) "s" else ""}) to DHT..."

            val group = repository.getGroup(contactId)
            val success = if (group != null) {
                repository.sendGroupVoiceNote(contactId, voiceBytes, result.durationMs, ttl)
            } else {
                repository.sendVoiceNote(contactId, voiceBytes, result.durationMs, ttl)
            }

            if (success) {
                _statusNotification.value = "PTT voice note sent ($frames DHT frame${if (frames > 1) "s" else ""})"
            } else {
                _statusNotification.value = "Failed to send voice note to DHT"
            }
        }
    }

    fun playVoiceNote(messageId: Long, voiceBytes: ByteArray) {
        if (_playingMessageId.value == messageId) {
            stopVoiceNote()
            return
        }
        _playingMessageId.value = messageId
        _playbackProgress.value = 0f
        voicePlayer.play(
            voiceBytes = voiceBytes,
            onProgress = { prog ->
                _playbackProgress.value = prog
            },
            onCompletion = {
                _playingMessageId.value = null
                _playbackProgress.value = 0f
            }
        )
    }

    fun stopVoiceNote() {
        voicePlayer.stop()
        _playingMessageId.value = null
        _playbackProgress.value = 0f
    }

    override fun onCleared() {
        super.onCleared()
        voiceRecorder.cancel()
        voicePlayer.stop()
        bobRepublishJob?.cancel()
        resetHandshakeState()
        if (app == null) {
            dhtLeafNode.stop()
            trafficGenerator.stop()
            pollingScheduler.stop()
        }
    }
}
