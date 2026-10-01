package io.github.dovecoteescapee.byedpi.core

import java.net.URI
import java.util.Locale

internal object DomainRules {
    fun normalize(value: String): String? {
        val source = value.trim()
        if (source.isEmpty()) return null
        val host = try {
            val candidate = if (source.contains("://")) source else "https://$source"
            URI(candidate).host ?: source.substringBefore('/').substringBefore(':')
        } catch (_: Exception) {
            source.substringBefore('/').substringBefore(':')
        }
        return host.trim().trim('.').lowercase(Locale.ROOT).takeIf { it.isNotEmpty() }
    }

    fun parse(lines: Sequence<String>): Set<String> = lines
        .map { it.substringBefore('#').trim().trimStart('.').lowercase(Locale.ROOT) }
        .filter { it.isNotEmpty() }
        .toSet()

    fun matches(rules: Set<String>, domain: String): Boolean {
        var current = domain
        while (true) {
            if (current in rules) return true
            val dot = current.indexOf('.')
            if (dot < 0) return false
            current = current.substring(dot + 1)
        }
    }
}
