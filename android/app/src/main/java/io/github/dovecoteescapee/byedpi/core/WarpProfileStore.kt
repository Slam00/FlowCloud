package io.github.dovecoteescapee.byedpi.core

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Text envelope for an encrypted profile: `v1:<base64 iv>:<base64 ciphertext>`.
 * Kept free of Android classes so it can be unit-tested on the JVM.
 */
object ProfileEnvelope {
    private const val VERSION = "v1"

    fun format(iv: String, ciphertext: String): String = "$VERSION:$iv:$ciphertext"

    /** Returns (iv, ciphertext) in base64, or null when [text] is not an envelope. */
    fun parse(text: String): Pair<String, String>? {
        val parts = text.split(':')
        if (parts.size != 3 || parts[0] != VERSION || parts[1].isEmpty() || parts[2].isEmpty()) return null
        return parts[1] to parts[2]
    }
}

/** AES-256-GCM with a non-exportable key held in the Android Keystore. */
class KeystoreProfileCipher(private val alias: String = DEFAULT_ALIAS) {
    companion object {
        const val DEFAULT_ALIAS = "flowcloud_warp_profile"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    fun encrypt(plain: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ciphertext = cipher.doFinal(plain)
        return ProfileEnvelope.format(
            Base64.encodeToString(cipher.iv, Base64.NO_WRAP),
            Base64.encodeToString(ciphertext, Base64.NO_WRAP),
        )
    }

    fun decrypt(envelope: String): ByteArray {
        val (iv, ciphertext) = ProfileEnvelope.parse(envelope)
            ?: throw IllegalArgumentException("Unsupported profile envelope")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(),
            GCMParameterSpec(TAG_BITS, Base64.decode(iv, Base64.NO_WRAP)),
        )
        return cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
    }

    fun deleteKey() {
        runCatching {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
        }
    }
}

/**
 * Stores the WARP profile (WireGuard and MASQUE private keys, account token)
 * encrypted with [KeystoreProfileCipher]. Profiles written by older versions in
 * plain SharedPreferences keys are migrated on first read and then removed.
 */
class WarpProfileStore(
    private val preferences: SharedPreferences,
    private val cipher: KeystoreProfileCipher = KeystoreProfileCipher(),
) {
    companion object {
        private const val TAG = "WarpProfileStore"
        private const val KEY_PROFILE = "profile_v2"
        private const val KEY_PROBE = "probe_v1"
        private val LEGACY_KEYS = listOf(
            "private_key", "peer_public_key", "endpoint", "address_v4", "address_v6",
        )
    }

    fun load(): WarpConfig? {
        preferences.getString(KEY_PROFILE, null)?.let { envelope ->
            return runCatching {
                WarpConfig.fromStorageJson(String(cipher.decrypt(envelope), Charsets.UTF_8))
            }.onFailure {
                // The Keystore key is gone (app data restored elsewhere, lock
                // screen reset on some vendors). The profile cannot be recovered;
                // drop it so the next start registers a fresh one.
                Log.w(TAG, "Encrypted WARP profile is unreadable; it will be re-registered", it)
                clear()
            }.getOrNull()
        }
        return migrateLegacy()
    }

    fun save(config: WarpConfig) {
        val envelope = cipher.encrypt(config.toStorageJson().toByteArray(Charsets.UTF_8))
        val editor = preferences.edit().putString(KEY_PROFILE, envelope)
        LEGACY_KEYS.forEach(editor::remove)
        if (!editor.commit()) {
            throw IllegalStateException("WARP profile could not be saved")
        }
    }

    /**
     * The second WARP device the route engine tests endpoints with, so test
     * handshakes never take the session of the live tunnel. Stored like the
     * main profile; a missing or unreadable one is simply registered again.
     */
    fun loadProbe(): WarpConfig? =
        preferences.getString(KEY_PROBE, null)?.let { envelope ->
            runCatching {
                WarpConfig.fromStorageJson(String(cipher.decrypt(envelope), Charsets.UTF_8))
            }.onFailure {
                Log.w(TAG, "Encrypted WARP probe profile is unreadable; it will be re-registered", it)
                preferences.edit().remove(KEY_PROBE).commit()
            }.getOrNull()
        }

    fun saveProbe(config: WarpConfig) {
        val envelope = cipher.encrypt(config.toStorageJson().toByteArray(Charsets.UTF_8))
        if (!preferences.edit().putString(KEY_PROBE, envelope).commit()) {
            throw IllegalStateException("WARP probe profile could not be saved")
        }
    }

    fun clear() {
        val editor = preferences.edit().remove(KEY_PROFILE).remove(KEY_PROBE)
        LEGACY_KEYS.forEach(editor::remove)
        editor.commit()
    }

    private fun migrateLegacy(): WarpConfig? {
        val privateKey = preferences.getString("private_key", null) ?: return null
        val publicKey = preferences.getString("peer_public_key", null) ?: return null
        val endpoint = preferences.getString("endpoint", null) ?: return null
        val addressV4 = preferences.getString("address_v4", "").orEmpty()
        val addressV6 = preferences.getString("address_v6", "").orEmpty()
        if (addressV4.isBlank() && addressV6.isBlank()) return null
        val config = WarpConfig(privateKey, publicKey, endpoint, addressV4, addressV6)
        runCatching { save(config) }
            .onSuccess { Log.i(TAG, "Plain-text WARP profile migrated to encrypted storage") }
            .onFailure { Log.w(TAG, "WARP profile migration failed; keeping the legacy copy", it) }
        return config
    }
}
