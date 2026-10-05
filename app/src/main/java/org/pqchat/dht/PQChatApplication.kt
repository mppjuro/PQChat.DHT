package org.pqchat.dht

import android.app.Application
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.security.Security

class PQChatApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Register Bouncy Castle Provider (includes PQC in 1.78+)
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }
}
