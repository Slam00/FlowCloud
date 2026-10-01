package io.github.dovecoteescapee.byedpi.core

import org.json.JSONObject

data class WireGuardKeyPair(
    val privateKey: String,
    val publicKey: String,
)

class AutoRouteProxy {
    companion object {
        init {
            System.loadLibrary("flowrouter")
            System.loadLibrary("byedpi")
        }
    }

    fun start(
        listenAddress: String,
        byeDpiAddress: String,
        dnsRelayAddress: String,
        warpRules: String,
        byeDpiRules: String,
        warpConfig: String,
    ) {
        val result = jniStart(
            listenAddress,
            byeDpiAddress,
            dnsRelayAddress,
            warpRules,
            byeDpiRules,
            warpConfig,
        )
        if (result != 0) {
            throw IllegalStateException(jniLastError().ifBlank { "Auto router failed with code $result" })
        }
    }

    fun stop() = jniStop()

    fun drainDiagnostics(): String = jniDrainDiagnostics()

    fun generateWireGuardKeyPair(): WireGuardKeyPair {
        val encoded = jniGenerateKeyPair()
        if (encoded.isBlank()) {
            throw IllegalStateException(jniLastError().ifBlank { "WireGuard key generation failed" })
        }
        val payload = JSONObject(encoded)
        return WireGuardKeyPair(
            privateKey = payload.getString("private_key"),
            publicKey = payload.getString("public_key"),
        )
    }

    private external fun jniStart(
        listenAddress: String,
        byeDpiAddress: String,
        dnsRelayAddress: String,
        warpRules: String,
        byeDpiRules: String,
        warpConfig: String,
    ): Int

    private external fun jniStop()
    private external fun jniLastError(): String
    private external fun jniDrainDiagnostics(): String
    private external fun jniGenerateKeyPair(): String
}
