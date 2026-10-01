package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import io.github.dovecoteescapee.byedpi.utility.getPreferences
import java.net.IDN
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Locale

data class SplitTunnelRules(
    val domains: List<String>,
    val networks: List<String>,
) {
    fun asRouterRules(): String = (domains + networks).joinToString("\n")
    fun domainsText(): String = domains.joinToString("\n")
    fun networksText(): String = networks.joinToString("\n")
}

class SplitTunnelRepository(context: Context) {
    companion object {
        private const val DOMAINS_KEY = "split_tunnel_warp_domains"
        private const val NETWORKS_KEY = "split_tunnel_warp_networks"

        internal fun normalizeDomain(value: String): String? {
            val normalized = DomainRules.normalize(value)?.trimStart('*', '.') ?: return null
            if (normalized.length > 253 || normalized.matches(Regex("[0-9.]+"))) return null
            val ascii = runCatching { IDN.toASCII(normalized) }.getOrNull()
                ?.lowercase(Locale.ROOT) ?: return null
            if (ascii.isEmpty() || ascii.split('.').any { label ->
                    label.isEmpty() || label.length > 63 ||
                        !label.matches(Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"))
                }) return null
            return ascii
        }

        internal fun normalizeNetwork(value: String): String? {
            val parts = value.trim().split('/')
            if (parts.size > 2) return null
            val address = parts[0]
            val isV6 = address.contains(':')
            val maxPrefix = if (isV6) 128 else 32
            val prefix = if (parts.size == 2) parts[1].toIntOrNull() ?: return null else maxPrefix
            if (prefix !in 0..maxPrefix) return null

            val validAddress = if (isV6) {
                address.matches(Regex("[0-9a-fA-F:.]+")) &&
                    runCatching { InetAddress.getByName(address) is Inet6Address }.getOrDefault(false)
            } else {
                val octets = address.split('.')
                octets.size == 4 && octets.all { octet ->
                    val number = octet.toIntOrNull()
                    octet.isNotEmpty() && octet.all(Char::isDigit) &&
                        number != null && number in 0..255
                }
            }
            if (!validAddress) return null
            val normalizedAddress = if (isV6) {
                address.lowercase(Locale.ROOT)
            } else {
                address.split('.').joinToString(".") { it.toInt().toString() }
            }
            return "$normalizedAddress/$prefix"
        }
    }

    private val preferences = context.getPreferences()

    fun load(): SplitTunnelRules = SplitTunnelRules(
        parseStored(preferences.getString(DOMAINS_KEY, "").orEmpty()),
        parseStored(preferences.getString(NETWORKS_KEY, "").orEmpty()),
    )

    fun validateAndSave(domainsText: String, networksText: String): SplitTunnelRules {
        val domains = inputLines(domainsText).mapIndexed { index, value ->
            normalizeDomain(value) ?: throw IllegalArgumentException(
                "Некорректный домен в строке ${index + 1}: $value"
            )
        }.distinct()
        val networks = inputLines(networksText).mapIndexed { index, value ->
            normalizeNetwork(value) ?: throw IllegalArgumentException(
                "Некорректный IP или CIDR в строке ${index + 1}: $value"
            )
        }.distinct()
        preferences.edit()
            .putString(DOMAINS_KEY, domains.joinToString("\n"))
            .putString(NETWORKS_KEY, networks.joinToString("\n"))
            .apply()
        return SplitTunnelRules(domains, networks)
    }

    private fun parseStored(value: String): List<String> = value.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .toList()

    private fun inputLines(value: String): List<String> = value.lineSequence()
        .map { it.substringBefore('#').trim() }
        .filter { it.isNotEmpty() }
        .toList()

}
