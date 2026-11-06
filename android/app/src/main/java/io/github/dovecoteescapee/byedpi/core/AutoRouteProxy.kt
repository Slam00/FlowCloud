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
        routerOptions: String = "",
    ) {
        // Options travel separately so the C start signature stays unchanged.
        if (jniSetOptions(routerOptions) != 0) {
            throw IllegalStateException(jniLastError().ifBlank { "Invalid route engine options" })
        }
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

    /**
     * Binds the router's outbound sockets (direct dials, WARP UDP) to [networkHandle]
     * (Network.getNetworkHandle(), 0 = system default). Applies to sockets opened after
     * the call, so call it before [start].
     */
    fun setPhysicalNetwork(networkHandle: Long) = jniSetPhysicalNetwork(networkHandle)

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

    /** Implemented in libflowrouter.so itself (flowrouter/bridge_jni_android.go). */
    private external fun jniSetOptions(options: String): Int
    private external fun jniStop()
    private external fun jniSetPhysicalNetwork(networkHandle: Long)
    private external fun jniLastError(): String
    private external fun jniDrainDiagnostics(): String
    private external fun jniGenerateKeyPair(): String
}
