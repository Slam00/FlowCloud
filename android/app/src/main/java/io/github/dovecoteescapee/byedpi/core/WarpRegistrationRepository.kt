package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import android.util.Base64
import android.util.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

/** Cloudflare MASQUE (CONNECT-IP) device, used when WireGuard UDP is blocked. */
data class MasqueConfig(
    val id: String,
    val token: String,
    /** PKCS#8 DER, base64. */
    val privateKey: String,
    /** PEM, as returned by the API. */
    val peerPublicKey: String,
    val addressV4: String,
    val addressV6: String,
) {
    fun toRouterJson(): JSONObject = JSONObject()
        .put("private_key", privateKey)
        .put("peer_public_key", peerPublicKey)
        .put("address_v4", addressV4)
        .put("address_v6", addressV6)

    fun toStorageJson(): JSONObject = toRouterJson()
        .put("id", id)
        .put("token", token)

    companion object {
        fun fromStorageJson(json: JSONObject): MasqueConfig? {
            val privateKey = json.optString("private_key")
            val peerPublicKey = json.optString("peer_public_key")
            if (privateKey.isBlank() || peerPublicKey.isBlank()) return null
            return MasqueConfig(
                id = json.optString("id"),
                token = json.optString("token"),
                privateKey = privateKey,
                peerPublicKey = peerPublicKey,
                addressV4 = json.optString("address_v4"),
                addressV6 = json.optString("address_v6"),
            )
        }
    }
}

data class WarpConfig(
    val privateKey: String,
    val peerPublicKey: String,
    val endpoint: String,
    val addressV4: String,
    val addressV6: String,
    /** Device id and token; empty for profiles registered before v0.2.30. */
    val id: String = "",
    val token: String = "",
    val masque: MasqueConfig? = null,
) {
    fun toRouterJson(): String = JSONObject()
        .put("private_key", privateKey)
        .put("peer_public_key", peerPublicKey)
        .put("endpoint", endpoint)
        .put("address_v4", addressV4)
        .put("address_v6", addressV6)
        .put("persistent_keepalive", 25)
        .apply { masque?.let { put("masque", it.toRouterJson()) } }
        .toString()

    fun toStorageJson(): String = JSONObject()
        .put("private_key", privateKey)
        .put("peer_public_key", peerPublicKey)
        .put("endpoint", endpoint)
        .put("address_v4", addressV4)
        .put("address_v6", addressV6)
        .put("id", id)
        .put("token", token)
        .apply { masque?.let { put("masque", it.toStorageJson()) } }
        .toString()

    val canRotate: Boolean get() = id.isNotBlank() && token.isNotBlank()

    companion object {
        fun fromStorageJson(text: String): WarpConfig {
            val json = JSONObject(text)
            return WarpConfig(
                privateKey = json.getString("private_key"),
                peerPublicKey = json.getString("peer_public_key"),
                endpoint = json.getString("endpoint"),
                addressV4 = json.optString("address_v4"),
                addressV6 = json.optString("address_v6"),
                id = json.optString("id"),
                token = json.optString("token"),
                masque = json.optJSONObject("masque")?.let(MasqueConfig::fromStorageJson),
            )
        }
    }
}

/**
 * Registers and maintains the WARP device.
 *
 * Registration tries both Cloudflare API hosts (api.devices.cloudflare.com is
 * the current one, api.cloudflareclient.com the older name) through ByeDPI
 * first and then directly, because either host can be filtered on a given
 * network. Request shapes follow WARPSCOUT
 * (https://github.com/vernette/warpscout, internal/warpscout/register.go and
 * masque.go, MIT License, Copyright (c) 2026 Nikita S.).
 */
class WarpRegistrationRepository(context: Context) {
    companion object {
        private const val TAG = "WarpRegistration"
        private val API_HOSTS = listOf("api.devices.cloudflare.com", "api.cloudflareclient.com")

        private const val WG_API_VERSION = "v0a4005"
        private const val WG_CLIENT_VERSION = "a-6.11-2223"
        private const val WG_USER_AGENT = "okhttp/3.12.1"

        private const val MASQUE_API_VERSION = "v0a4471"
        private const val MASQUE_CLIENT_VERSION = "a-6.35-4471"
        private const val MASQUE_USER_AGENT = "WARP for Android"

        /** Consecutive starts with a failed WARP round before the key is rotated. */
        private const val ROTATE_AFTER_FAILURES = 3
        private const val ROTATE_MIN_INTERVAL_MS = 24L * 60 * 60 * 1000
        private const val MASQUE_RETRY_INTERVAL_MS = 6L * 60 * 60 * 1000

        private val JSON = "application/json".toMediaType()

        /** Serializes profile changes made from the VPN start path and background work. */
        private val lock = Any()
    }

    private val store = WarpProfileStore(context.getSharedPreferences("warp", Context.MODE_PRIVATE))
    private val state = context.getSharedPreferences("warp_state", Context.MODE_PRIVATE)
    private val random = SecureRandom()

    private class Api(val client: OkHttpClient, val baseUrl: String, val label: String)

    private fun utcTimestamp(): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date())

    private fun randomBase64(size: Int): String =
        Base64.encodeToString(ByteArray(size).also(random::nextBytes), Base64.NO_WRAP)

    private fun client(byeDpiPort: Int?): OkHttpClient = OkHttpClient.Builder()
        .apply {
            if (byeDpiPort != null) {
                // ByeDPI resolves the host remotely and splits the TLS ClientHello,
                // which gets through networks that filter the API host by SNI.
                proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved("127.0.0.1", byeDpiPort)))
            }
        }
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .callTimeout(12, TimeUnit.SECONDS)
        .build()

    /** Every (transport, host) pair, most likely to work first. */
    private fun apis(byeDpiPort: Int, apiVersion: String): List<Api> {
        val transports = listOf("ByeDPI" to client(byeDpiPort), "direct" to client(null))
        return transports.flatMap { (label, client) ->
            API_HOSTS.map { host -> Api(client, "https://$host/$apiVersion/reg", "$label/$host") }
        }
    }

    private fun <T> firstWorking(apis: List<Api>, operation: String, block: (Api) -> T): T {
        val errors = mutableListOf<String>()
        for (api in apis) {
            try {
                return block(api).also { Log.i(TAG, "$operation succeeded via ${api.label}") }
            } catch (error: Exception) {
                errors += "${api.label}: ${error.message}"
                Log.w(TAG, "$operation failed via ${api.label}: ${error.message}")
            }
        }
        throw IllegalStateException("$operation failed: ${errors.joinToString("; ")}")
    }

    private fun call(
        api: Api,
        method: String,
        url: String,
        payload: JSONObject,
        token: String = "",
        userAgent: String = WG_USER_AGENT,
        clientVersion: String = WG_CLIENT_VERSION,
    ): JSONObject {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", userAgent)
            .header("CF-Client-Version", clientVersion)
            .apply { if (token.isNotBlank()) header("Authorization", "Bearer $token") }
            .method(method, payload.toString().toRequestBody(JSON))
            .build()
        api.client.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw IllegalStateException("HTTP ${response.code}")
            }
            if (body.isBlank()) throw IllegalStateException("empty response")
            return JSONObject(body)
        }
    }

    fun getOrRegister(byeDpiPort: Int): WarpConfig = synchronized(lock) {
        store.load()?.let {
            Log.i(TAG, "Using stored WARP profile")
            return it
        }
        val result = register(byeDpiPort)
        store.save(result)
        Log.i(TAG, "WARP profile registered successfully")
        result
    }

    private fun register(byeDpiPort: Int): WarpConfig {
        val pair = AutoRouteProxy().generateWireGuardKeyPair()
        val payload = JSONObject()
            .put("fcm_token", "")
            .put("install_id", "")
            .put("key", pair.publicKey)
            .put("locale", "en_US")
            .put("model", "Android")
            .put("tos", utcTimestamp())
            .put("type", "Android")
        return firstWorking(apis(byeDpiPort, WG_API_VERSION), "WARP registration") { api ->
            val response = call(api, "POST", api.baseUrl, payload)
            val config = parseWireGuard(response, pair.privateKey, response.optString("id"), response.optString("token"))
            if (config.canRotate) {
                runCatching {
                    call(api, "PATCH", "${api.baseUrl}/${config.id}", JSONObject().put("warp_enabled", true), config.token)
                }.onFailure { Log.w(TAG, "warp_enabled update failed: ${it.message}") }
            }
            config
        }
    }

    private fun parseWireGuard(response: JSONObject, privateKey: String, id: String, token: String): WarpConfig {
        val config = response.getJSONObject("config")
        val addresses = config.getJSONObject("interface").getJSONObject("addresses")
        val peer = config.getJSONArray("peers").getJSONObject(0)
        val endpointData = peer.getJSONObject("endpoint")
        return WarpConfig(
            privateKey = privateKey,
            peerPublicKey = peer.getString("public_key"),
            endpoint = normalizeEndpoint(endpointData.optString("v4").ifBlank { endpointData.getString("host") }),
            addressV4 = addresses.optString("v4"),
            addressV6 = addresses.optString("v6"),
            id = id,
            token = token,
        )
    }

    /**
     * Swaps the WireGuard key of the existing device, keeping its id and token.
     * Profiles without credentials (registered by older versions) get a fresh
     * registration instead.
     */
    fun rotateKey(byeDpiPort: Int): WarpConfig = synchronized(lock) {
        val existing = store.load()
        val rotated = if (existing != null && existing.canRotate) {
            val pair = AutoRouteProxy().generateWireGuardKeyPair()
            runCatching {
                firstWorking(apis(byeDpiPort, WG_API_VERSION), "WARP key rotation") { api ->
                    val response = call(
                        api, "PATCH", "${api.baseUrl}/${existing.id}",
                        JSONObject().put("key", pair.publicKey), existing.token,
                    )
                    parseWireGuard(response, pair.privateKey, existing.id, existing.token)
                        .copy(masque = existing.masque)
                }
            }.getOrElse {
                Log.w(TAG, "Key rotation failed; registering a fresh device", it)
                register(byeDpiPort).copy(masque = existing.masque)
            }
        } else {
            register(byeDpiPort).copy(masque = existing?.masque)
        }
        store.save(rotated)
        rotated
    }

    /**
     * Records whether the route engine found a working WARP endpoint at start.
     * After several consecutive failed starts the WireGuard key is rotated once a
     * day at most: a device Cloudflare stopped serving fails every endpoint.
     * Returns true when the profile changed.
     */
    fun reportWarpState(engineState: String, byeDpiPort: Int): Boolean {
        when (engineState) {
            "ok" -> {
                state.edit().putInt("consecutive_failures", 0).apply()
                return false
            }
            "failed" -> Unit
            else -> return false
        }
        val failures = state.getInt("consecutive_failures", 0) + 1
        state.edit().putInt("consecutive_failures", failures).apply()
        val now = System.currentTimeMillis()
        val lastRotation = state.getLong("last_rotation_at", 0L)
        if (failures < ROTATE_AFTER_FAILURES || now - lastRotation < ROTATE_MIN_INTERVAL_MS) {
            return false
        }
        state.edit().putLong("last_rotation_at", now).putInt("consecutive_failures", 0).apply()
        return runCatching { rotateKey(byeDpiPort) }
            .onSuccess { Log.i(TAG, "WARP key rotated after $failures failed starts") }
            .onFailure { Log.w(TAG, "WARP key rotation failed", it) }
            .isSuccess
    }

    /**
     * Adds a MASQUE device to the stored profile if it has none yet. Failures
     * are retried at most every few hours. Returns true when the profile changed.
     */
    fun ensureMasque(byeDpiPort: Int): Boolean {
        synchronized(lock) {
            val existing = store.load() ?: return false
            if (existing.masque != null) return false
            val now = System.currentTimeMillis()
            if (now - state.getLong("masque_attempt_at", 0L) < MASQUE_RETRY_INTERVAL_MS) return false
            state.edit().putLong("masque_attempt_at", now).apply()
            val masque = runCatching { registerMasque(byeDpiPort) }
                .onFailure { Log.w(TAG, "MASQUE registration failed", it) }
                .getOrNull() ?: return false
            // Re-read: a rotation may have replaced the profile meanwhile.
            val current = store.load() ?: existing
            store.save(current.copy(masque = masque))
            Log.i(TAG, "MASQUE device registered")
            return true
        }
    }

    private fun registerMasque(byeDpiPort: Int): MasqueConfig {
        val generator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), random)
        }
        val keyPair = generator.generateKeyPair()
        // The first request must look like a stock WireGuard enrolment; its key is
        // a throwaway the API only checks the shape of.
        val enrol = JSONObject()
            .put("key", randomBase64(32))
            .put("install_id", "")
            .put("fcm_token", "")
            .put("tos", utcTimestamp())
            .put("model", "PC")
            .put("serial_number", randomBase64(8))
            .put("os_version", "10")
            .put("key_type", "curve25519")
            .put("tunnel_type", "wireguard")
            .put("locale", "en_US")
        return firstWorking(apis(byeDpiPort, MASQUE_API_VERSION), "MASQUE registration") { api ->
            val first = call(
                api, "POST", api.baseUrl, enrol,
                userAgent = MASQUE_USER_AGENT, clientVersion = MASQUE_CLIENT_VERSION,
            )
            val id = first.optString("id")
            val token = first.optString("token")
            if (id.isBlank() || token.isBlank()) throw IllegalStateException("response has no id or token")
            val enrolled = call(
                api, "PATCH", "${api.baseUrl}/$id",
                JSONObject()
                    .put("key", Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP))
                    .put("key_type", "secp256r1")
                    .put("tunnel_type", "masque")
                    .put("name", "flowcloud"),
                token,
                userAgent = MASQUE_USER_AGENT, clientVersion = MASQUE_CLIENT_VERSION,
            )
            val config = enrolled.getJSONObject("config")
            val peerKey = config.getJSONArray("peers").getJSONObject(0).getString("public_key")
            val addresses = config.getJSONObject("interface").getJSONObject("addresses")
            MasqueConfig(
                id = id,
                token = token,
                privateKey = Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP),
                peerPublicKey = peerKey,
                addressV4 = addresses.optString("v4"),
                addressV6 = addresses.optString("v6"),
            )
        }
    }

    private fun normalizeEndpoint(value: String): String {
        val endpoint = value.trim()
        return if (endpoint.endsWith(":0")) {
            endpoint.dropLast(2) + ":2408"
        } else {
            endpoint
        }
    }
}
