package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import io.github.dovecoteescapee.byedpi.data.BlockDecision
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

class BlocklistRepository(private val context: Context) {
    companion object {
        const val INSIDE_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst"
        const val GEOBLOCK_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst"
        const val BLOCK_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/block.lst"
        private const val SERVICES_BASE_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services"
        const val TELEGRAM_IPV4_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/telegram.lst"
        const val TELEGRAM_IPV6_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv6/telegram.lst"
        const val META_IPV4_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/meta.lst"
        const val META_IPV6_URL =
            "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv6/meta.lst"
        private const val UPDATE_INTERVAL_MS = 24L * 60L * 60L * 1000L
        private val SERVICE_LISTS = listOf(
            "cloudflare.lst",
            "cloudfront.lst",
            "digitalocean.lst",
            "discord.lst",
            "google_ai.lst",
            "google_meet.lst",
            "google_play.lst",
            "hdrezka.lst",
            "hetzner.lst",
            "meta.lst",
            "ovh.lst",
            "roblox.lst",
            "telegram.lst",
            "tiktok.lst",
            "twitter.lst",
            "youtube.lst",
        )
        private val WARP_OVERRIDES = listOf(
            // Speedtest is present in inside-raw/block, but ByeDPI alone does
            // not open it on some mobile carriers. WARP must win when a domain
            // appears in both routing sets.
            "speedtest.net",
            "speedtestcustom.com",
            "speedtestserver.com",
            "ookla.com",
            "ooklaserver.net",
        ).joinToString("\n")
    }

    private val directory = File(context.filesDir, "blocklists")

    fun normalizeDomain(value: String): String? = DomainRules.normalize(value)

    fun decide(value: String): BlockDecision {
        val domain = normalizeDomain(value) ?: return BlockDecision.ByeDpi
        return if (
            DomainRules.matches(load("inside-raw.lst"), domain) ||
            DomainRules.matches(load("block.lst"), domain) ||
            DomainRules.matches(load("geoblock.lst"), domain) ||
            DomainRules.matches(load("meta.lst"), domain)
        ) {
            BlockDecision.Warp
        } else {
            BlockDecision.ByeDpi
        }
    }

    fun isKnownBlocked(value: String): Boolean {
        val domain = normalizeDomain(value) ?: return false
        return DomainRules.matches(load("inside-raw.lst"), domain) ||
            DomainRules.matches(load("block.lst"), domain) ||
            DomainRules.matches(load("geoblock.lst"), domain) ||
            DomainRules.matches(load("meta.lst"), domain)
    }

    fun byeDpiRoutingRules(): String = listOf(
        "inside-raw.lst",
        "block.lst",
    ).plus(SERVICE_LISTS).joinToString("\n") { loadText(it) }

    fun warpRoutingRules(): String = (listOf(WARP_OVERRIDES) +
        (listOf("geoblock.lst") + SERVICE_LISTS + listOf(
            "telegram-ipv4.lst",
            "telegram-ipv6.lst",
            "meta-ipv4.lst",
            "meta-ipv6.lst",
        )).map { loadText(it) }).joinToString("\n")

    suspend fun updateIfNeeded(force: Boolean = false): Boolean = withContext(Dispatchers.IO) {
        directory.mkdirs()
        val marker = File(directory, "updated-at")
        if (!force && marker.exists() && System.currentTimeMillis() - marker.lastModified() < UPDATE_INTERVAL_MS) {
            return@withContext false
        }
        val inside = download(INSIDE_URL)
        val block = download(BLOCK_URL)
        val geoblock = download(GEOBLOCK_URL)
        val services = SERVICE_LISTS.associateWith { name ->
            download("$SERVICES_BASE_URL/$name")
        }
        val telegramIpv4 = download(TELEGRAM_IPV4_URL)
        val telegramIpv6 = download(TELEGRAM_IPV6_URL)
        val metaIpv4 = download(META_IPV4_URL)
        val metaIpv6 = download(META_IPV6_URL)
        writeAtomic("inside-raw.lst", inside)
        writeAtomic("block.lst", block)
        writeAtomic("geoblock.lst", geoblock)
        services.forEach { (name, content) -> writeAtomic(name, content) }
        writeAtomic("telegram-ipv4.lst", telegramIpv4)
        writeAtomic("telegram-ipv6.lst", telegramIpv6)
        writeAtomic("meta-ipv4.lst", metaIpv4)
        writeAtomic("meta-ipv6.lst", metaIpv6)
        marker.writeText(System.currentTimeMillis().toString())
        true
    }

    private fun load(name: String): Set<String> {
        return DomainRules.parse(loadText(name).lineSequence())
    }

    private fun loadText(name: String): String {
        val local = File(directory, name)
        return if (local.isFile) {
            local.readText()
        } else {
            context.assets.open(name).bufferedReader().use { it.readText() }
        }
    }

    private fun download(address: String): String {
        val connection = URL(address).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.setRequestProperty("User-Agent", "FlowCloud-Android/0.1")
        try {
            if (connection.responseCode !in 200..299) {
                throw IllegalStateException("HTTP ${connection.responseCode} while updating lists")
            }
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally {
            connection.disconnect()
        }
    }

    private fun writeAtomic(name: String, content: String) {
        val target = File(directory, name)
        val temporary = File(directory, "$name.tmp")
        temporary.writeText(content)
        if (!temporary.renameTo(target)) {
            temporary.copyTo(target, overwrite = true)
            temporary.delete()
        }
    }
}
