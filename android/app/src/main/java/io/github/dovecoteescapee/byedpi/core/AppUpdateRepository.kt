package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import io.github.dovecoteescapee.byedpi.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class AppRelease(
    val version: String,
    val title: String,
    val notes: String,
    val downloadUrl: String,
    val size: Long,
    val sha256: String,
)

sealed interface UpdateCheckResult {
    data class Available(val release: AppRelease) : UpdateCheckResult
    data object UpToDate : UpdateCheckResult
    data object NotPublished : UpdateCheckResult
}

class UpdateVerificationException(message: String) : IOException(message)

class AppUpdateRepository(private val context: Context) {
    companion object {
        private const val RELEASE_API =
            "https://api.github.com/repos/Slam00/FlowCloud/releases/latest"
        private const val CHECK_INTERVAL_MS = 24L * 60L * 60L * 1_000L
        private const val LAST_CHECK_KEY = "last_check"
        private const val MAX_APK_SIZE = 250L * 1024L * 1024L
    }

    private val preferences = context.getSharedPreferences("app_updates", Context.MODE_PRIVATE)
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(90, TimeUnit.SECONDS)
        .build()

    fun shouldCheckAutomatically(now: Long = System.currentTimeMillis()): Boolean {
        return now - preferences.getLong(LAST_CHECK_KEY, 0L) >= CHECK_INTERVAL_MS
    }

    suspend fun check(): UpdateCheckResult = withContext(Dispatchers.IO) {
        markChecked()
        val request = Request.Builder()
            .url(RELEASE_API)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "FlowCloud-Android/${BuildConfig.VERSION_NAME}")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code == 404) {
                return@withContext UpdateCheckResult.NotPublished
            }
            if (!response.isSuccessful) {
                throw IOException("GitHub returned HTTP ${response.code}")
            }

            val payload = response.body?.string()
                ?: throw IOException("Empty GitHub response")
            val release = parseRelease(JSONObject(payload))

            if (!VersionNameComparator.isNewer(release.version, BuildConfig.VERSION_NAME)) {
                UpdateCheckResult.UpToDate
            } else {
                UpdateCheckResult.Available(release)
            }
        }
    }

    suspend fun download(release: AppRelease): File = withContext(Dispatchers.IO) {
        if (release.size <= 0L || release.size > MAX_APK_SIZE) {
            throw UpdateVerificationException("Invalid APK size")
        }

        val updateDirectory = File(context.cacheDir, "updates").apply { mkdirs() }
        val safeVersion = release.version.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val destination = File(updateDirectory, "FlowCloud-$safeVersion.apk")
        val temporary = File(updateDirectory, "FlowCloud-$safeVersion.apk.part")
        destination.delete()
        temporary.delete()

        val request = Request.Builder()
            .url(release.downloadUrl)
            .header("Accept", "application/octet-stream")
            .header("User-Agent", "FlowCloud-Android/${BuildConfig.VERSION_NAME}")
            .build()

        try {
            val digest = MessageDigest.getInstance("SHA-256")
            var written = 0L
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("APK download returned HTTP ${response.code}")
                }
                response.body?.byteStream()?.use { input ->
                    temporary.outputStream().buffered().use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            written += count
                            if (written > MAX_APK_SIZE) {
                                throw UpdateVerificationException("APK is too large")
                            }
                            digest.update(buffer, 0, count)
                            output.write(buffer, 0, count)
                        }
                    }
                } ?: throw IOException("Empty APK response")
            }

            if (written != release.size) {
                throw UpdateVerificationException("APK size does not match release metadata")
            }
            val actualDigest = digest.digest().joinToString("") { "%02x".format(it) }
            if (!actualDigest.equals(release.sha256, ignoreCase = true)) {
                throw UpdateVerificationException("APK SHA-256 does not match release metadata")
            }
            verifyPackage(temporary)
            if (!temporary.renameTo(destination)) {
                temporary.copyTo(destination, overwrite = true)
                temporary.delete()
            }
            destination
        } catch (error: Throwable) {
            temporary.delete()
            destination.delete()
            throw error
        }
    }

    private fun parseRelease(payload: JSONObject): AppRelease {
        val version = payload.optString("tag_name").trim()
        if (VersionNameComparator.parts(version).isEmpty()) {
            throw IOException("Release tag does not contain a version")
        }

        val assets = payload.optJSONArray("assets")
            ?: throw IOException("Release has no assets")
        val candidates = buildList {
            for (index in 0 until assets.length()) {
                val asset = assets.optJSONObject(index) ?: continue
                if (asset.optString("name").endsWith(".apk", ignoreCase = true) &&
                    asset.optString("state") == "uploaded"
                ) {
                    add(asset)
                }
            }
        }
        val apk = candidates.minByOrNull { assetPriority(it.optString("name")) }
            ?: throw IOException("Release has no FlowCloud APK")
        val digest = apk.optString("digest")
            .removePrefix("sha256:")
            .trim()
        if (!digest.matches(Regex("[0-9a-fA-F]{64}"))) {
            throw IOException("Release APK has no SHA-256 digest")
        }

        return AppRelease(
            version = version,
            title = payload.optString("name").ifBlank { version },
            notes = payload.optString("body").trim().take(4_000),
            downloadUrl = apk.getString("browser_download_url"),
            size = apk.getLong("size"),
            sha256 = digest,
        )
    }

    private fun assetPriority(name: String): Int = when {
        name.equals("FlowCloud-Android.apk", ignoreCase = true) -> 0
        name.equals("FlowCloud-Android-release.apk", ignoreCase = true) -> 1
        name.contains("flowcloud", ignoreCase = true) -> 2
        else -> 3
    }

    private fun markChecked() {
        preferences.edit().putLong(LAST_CHECK_KEY, System.currentTimeMillis()).apply()
    }

    @Suppress("DEPRECATION")
    private fun verifyPackage(apk: File) {
        val manager = context.packageManager
        val signingFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val current = manager.getPackageInfo(context.packageName, signingFlag)
        val downloaded = manager.getPackageArchiveInfo(apk.absolutePath, signingFlag)
            ?: throw UpdateVerificationException("Downloaded file is not an APK")
        if (downloaded.packageName != context.packageName) {
            throw UpdateVerificationException("APK package name does not match")
        }

        val currentSigners = signerDigests(current)
        val downloadedSigners = signerDigests(downloaded)
        if (currentSigners.isEmpty() || downloadedSigners.isEmpty() ||
            currentSigners.intersect(downloadedSigners).isEmpty()
        ) {
            throw UpdateVerificationException("APK signature does not match installed app")
        }
    }

    @Suppress("DEPRECATION")
    private fun signerDigests(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo ?: return emptySet()
            signingInfo.signingCertificateHistory ?: signingInfo.apkContentsSigners
        } else {
            info.signatures
        } ?: return emptySet()

        return signatures.mapTo(mutableSetOf()) { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString("") { "%02x".format(it) }
        }
    }
}

internal object VersionNameComparator {
    private val versionPattern = Regex("\\d+(?:\\.\\d+)*")

    fun parts(value: String): List<Int> = versionPattern.find(value)
        ?.value
        ?.split('.')
        ?.mapNotNull(String::toIntOrNull)
        .orEmpty()

    fun isNewer(candidate: String, installed: String): Boolean {
        val candidateParts = parts(candidate)
        val installedParts = parts(installed)
        if (candidateParts.isEmpty() || installedParts.isEmpty()) return false
        val count = maxOf(candidateParts.size, installedParts.size)
        for (index in 0 until count) {
            val left = candidateParts.getOrElse(index) { 0 }
            val right = installedParts.getOrElse(index) { 0 }
            if (left != right) return left > right
        }
        return false
    }
}
