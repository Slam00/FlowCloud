package io.github.dovecoteescapee.byedpi.core

import org.json.JSONObject

data class WireGuardKeyPair(
    val privateKey: String,
    val publicKey: String,
)

/** What the main screen shows about the WARP route; [pingMs] is -1 when unknown. */
data class WarpRouteInfo(
    val state: String,
    val endpoint: String,
    val transport: String,
    val pingMs: Long,
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

    /** WARP route state of the running router: ok, failed, idle or unavailable. */
    fun warpState(): String = runCatching { jniWarpState() }.getOrDefault("unavailable")

    /**
     * The WARP endpoint in use and, with [measurePing], the round trip through
     * the tunnel. Measuring blocks for up to a few seconds: call off the main thread.
     */
    fun warpInfo(measurePing: Boolean): WarpRouteInfo = runCatching {
        val payload = JSONObject(jniWarpInfo(measurePing))
        WarpRouteInfo(
            state = payload.optString("state", "unavailable"),
            endpoint = payload.optString("endpoint"),
            transport = payload.optString("transport"),
            pingMs = payload.optLong("ping_ms", -1L),
        )
    }.getOrDefault(WarpRouteInfo("unavailable", "", "", -1L))

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

    /** Implemented in libflowrouter.so itself (flowrouter/bridge_jni_android.go). */
    private external fun jniWarpState(): String

    /** Implemented in libflowrouter.so itself (flowrouter/bridge_jni_android.go). */
    private external fun jniWarpInfo(measurePing: Boolean): String
    private external fun jniStop()
    private external fun jniSetPhysicalNetwork(networkHandle: Long)
    private external fun jniLastError(): String
    private external fun jniDrainDiagnostics(): String
    private external fun jniGenerateKeyPair(): String
}
