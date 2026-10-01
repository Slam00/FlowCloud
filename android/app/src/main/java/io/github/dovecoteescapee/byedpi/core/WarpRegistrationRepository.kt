package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import android.util.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Proxy
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

data class WarpConfig(
    val privateKey: String,
    val peerPublicKey: String,
    val endpoint: String,
    val addressV4: String,
    val addressV6: String,
) {
    fun toRouterJson(): String = JSONObject()
        .put("private_key", privateKey)
        .put("peer_public_key", peerPublicKey)
        .put("endpoint", endpoint)
        .put("address_v4", addressV4)
        .put("address_v6", addressV6)
        .put("persistent_keepalive", 25)
        .toString()

}

class WarpRegistrationRepository(context: Context) {
    companion object {
        private const val TAG = "WarpRegistration"
        private const val API = "https://api.cloudflareclient.com/v0a4005/reg"
        private const val CLIENT_VERSION = "a-6.11-2223"
    }

    private val preferences = context.getSharedPreferences("warp", Context.MODE_PRIVATE)

    private fun utcTimestamp(): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date())

    fun getOrRegister(byeDpiPort: Int): WarpConfig {
        load()?.let {
            Log.i(TAG, "Using cached WARP profile")
            return it
        }
        val pair = AutoRouteProxy().generateWireGuardKeyPair()
        val payload = JSONObject()
            .put("fcm_token", "")
            .put("install_id", "")
            .put("key", pair.publicKey)
            .put("locale", "en_US")
            .put("model", "Android")
            .put("tos", utcTimestamp())
            .put("type", "Android")

        val client = OkHttpClient.Builder()
            // The registration host itself can be filtered on mobile networks.
            // ByeDPI is already listening when this method runs, so let its SOCKS
            // handshake resolve the hostname remotely and split the TLS ClientHello.
            .proxy(
                Proxy(
                    Proxy.Type.SOCKS,
                    InetSocketAddress.createUnresolved("127.0.0.1", byeDpiPort),
                ),
            )
            .connectTimeout(6, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .callTimeout(12, TimeUnit.SECONDS)
            .build()
        val request = Request.Builder()
            .url(API)
            .header("User-Agent", "okhttp/3.12.1")
            .header("CF-Client-Version", CLIENT_VERSION)
            .post(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(request).execute().use { httpResponse ->
            if (!httpResponse.isSuccessful) {
                throw IllegalStateException("Cloudflare registration returned HTTP ${httpResponse.code}")
            }
            val body = httpResponse.body?.string()
                ?: throw IllegalStateException("Cloudflare registration returned an empty response")
            val response = JSONObject(body)
            val config = response.getJSONObject("config")
            val addresses = config.getJSONObject("interface").getJSONObject("addresses")
            val peer = config.getJSONArray("peers").getJSONObject(0)
            val endpointData = peer.getJSONObject("endpoint")
            val result = WarpConfig(
                privateKey = pair.privateKey,
                peerPublicKey = peer.getString("public_key"),
                endpoint = normalizeEndpoint(
                    endpointData.optString("v4").ifBlank { endpointData.getString("host") },
                ),
                addressV4 = addresses.optString("v4"),
                addressV6 = addresses.optString("v6"),
            )
            save(result)
            Log.i(TAG, "WARP profile registered successfully")
            return result
        }
    }

    private fun load(): WarpConfig? {
        val privateKey = preferences.getString("private_key", null) ?: return null
        val publicKey = preferences.getString("peer_public_key", null) ?: return null
        val endpoint = normalizeEndpoint(preferences.getString("endpoint", null) ?: return null)
        val addressV4 = preferences.getString("address_v4", "").orEmpty()
        val addressV6 = preferences.getString("address_v6", "").orEmpty()
        if (addressV4.isBlank() && addressV6.isBlank()) return null
        return WarpConfig(privateKey, publicKey, endpoint, addressV4, addressV6)
    }

    private fun normalizeEndpoint(value: String): String {
        val endpoint = value.trim()
        return if (endpoint.endsWith(":0")) {
            endpoint.dropLast(2) + ":2408"
        } else {
            endpoint
        }
    }

    private fun save(config: WarpConfig) {
        preferences.edit()
            .putString("private_key", config.privateKey)
            .putString("peer_public_key", config.peerPublicKey)
            .putString("endpoint", config.endpoint)
            .putString("address_v4", config.addressV4)
            .putString("address_v6", config.addressV6)
            .apply()
    }
}
