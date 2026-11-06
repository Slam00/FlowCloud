package io.github.dovecoteescapee.byedpi.core

import android.content.SharedPreferences
import io.github.dovecoteescapee.byedpi.utility.getStringNotNull
import io.github.dovecoteescapee.byedpi.utility.shellSplit

sealed interface ByeDpiProxyPreferences {
    companion object {
        fun fromSharedPreferences(preferences: SharedPreferences): ByeDpiProxyPreferences =
            when (preferences.getBoolean("byedpi_enable_cmd_settings", false)) {
                true -> ByeDpiProxyCmdPreferences(preferences)
                false -> ByeDpiProxyUIPreferences(preferences)
            }
    }
}

class ByeDpiProxyCmdPreferences(val args: Array<String>) : ByeDpiProxyPreferences {
    constructor(cmd: String) : this(cmdToArgs(cmd))

    constructor(preferences: SharedPreferences) : this(
        preferences.getStringNotNull(
            "byedpi_cmd_args",
            ""
        )
    )

    companion object {
        private fun cmdToArgs(cmd: String): Array<String> {
            val firstArgIndex = cmd.indexOf("-")
            val argsStr = (if (firstArgIndex > 0) cmd.substring(firstArgIndex) else cmd).trim()
            return arrayOf("ciadpi") + shellSplit(argsStr).filter { it !in IGNORED_ARGS }
        }

        // Options that would make the in-app core exit right away instead of serving.
        private val IGNORED_ARGS = setOf("-h", "--help", "-v", "--version", "-D", "--daemon")
    }
}

class ByeDpiProxyUIPreferences(
    ip: String? = null,
    port: Int? = null,
    maxConnections: Int? = null,
    bufferSize: Int? = null,
    defaultTtl: Int? = null,
    noDomain: Boolean? = null,
    desyncHttp: Boolean? = null,
    desyncHttps: Boolean? = null,
    desyncUdp: Boolean? = null,
    desyncMethod: DesyncMethod? = null,
    splitPosition: Int? = null,
    splitAtHost: Boolean? = null,
    fakeTtl: Int? = null,
    fakeSni: String? = null,
    oobChar: String? = null,
    hostMixedCase: Boolean? = null,
    domainMixedCase: Boolean? = null,
    hostRemoveSpaces: Boolean? = null,
    tlsRecordSplit: Boolean? = null,
    tlsRecordSplitPosition: Int? = null,
    tlsRecordSplitAtSni: Boolean? = null,
    hostsMode: HostsMode? = null,
    hosts: String? = null,
    tcpFastOpen: Boolean? = null,
    udpFakeCount: Int? = null,
    dropSack: Boolean? = null,
    byedpiFakeOffset: Int? = null,
) : ByeDpiProxyPreferences {
    val ip: String = ip ?: "127.0.0.1"
    val port: Int = port ?: 1080
    val maxConnections: Int = maxConnections ?: 512
    val bufferSize: Int = bufferSize ?: 16384
    val defaultTtl: Int = defaultTtl ?: 0
    val customTtl: Boolean = defaultTtl != null
    val noDomain: Boolean = noDomain ?: false
    val desyncHttp: Boolean = desyncHttp ?: true
    val desyncHttps: Boolean = desyncHttps ?: true
    val desyncUdp: Boolean = desyncUdp ?: false
    val desyncMethod: DesyncMethod = desyncMethod ?: DesyncMethod.Disorder
    val splitPosition: Int = splitPosition ?: 1
    val splitAtHost: Boolean = splitAtHost ?: false
    val fakeTtl: Int = fakeTtl ?: 8
    val fakeSni: String = fakeSni ?: "www.iana.org"
    val oobChar: Byte = (oobChar ?: "a")[0].code.toByte()
    val hostMixedCase: Boolean = hostMixedCase ?: false
    val domainMixedCase: Boolean = domainMixedCase ?: false
    val hostRemoveSpaces: Boolean = hostRemoveSpaces ?: false
    val tlsRecordSplit: Boolean = tlsRecordSplit ?: true
    val tlsRecordSplitPosition: Int = tlsRecordSplitPosition ?: 1
    val tlsRecordSplitAtSni: Boolean = tlsRecordSplitAtSni ?: true
    val hostsMode: HostsMode =
        if (hosts?.isBlank() != false) HostsMode.Disable
        else hostsMode ?: HostsMode.Disable
    val hosts: String? =
        if (this.hostsMode == HostsMode.Disable) null
        else hosts?.trim()
    val tcpFastOpen: Boolean = tcpFastOpen ?: false
    val udpFakeCount: Int = udpFakeCount ?: 0
    val dropSack: Boolean = dropSack ?: false
    val fakeOffset: Int = byedpiFakeOffset ?: 0

    constructor(preferences: SharedPreferences) : this(
        ip = preferences.getString("byedpi_proxy_ip", null),
        port = preferences.getString("byedpi_proxy_port", null)?.toIntOrNull(),
        maxConnections = preferences.getString("byedpi_max_connections", null)?.toIntOrNull(),
        bufferSize = preferences.getString("byedpi_buffer_size", null)?.toIntOrNull(),
        defaultTtl = preferences.getString("byedpi_default_ttl", null)?.toIntOrNull(),
        noDomain = preferences.getBoolean("byedpi_no_domain", false),
        desyncHttp = preferences.getBoolean("byedpi_desync_http", true),
        desyncHttps = preferences.getBoolean("byedpi_desync_https", true),
        desyncUdp = preferences.getBoolean("byedpi_desync_udp", false),
        desyncMethod = preferences.getString("byedpi_desync_method", null)
            ?.let { DesyncMethod.fromName(it) },
        splitPosition = preferences.getString("byedpi_split_position", null)?.toIntOrNull(),
        splitAtHost = preferences.getBoolean("byedpi_split_at_host", false),
        fakeTtl = preferences.getString("byedpi_fake_ttl", null)?.toIntOrNull(),
        fakeSni = preferences.getString("byedpi_fake_sni", null),
        oobChar = preferences.getString("byedpi_oob_data", null),
        hostMixedCase = preferences.getBoolean("byedpi_host_mixed_case", false),
        domainMixedCase = preferences.getBoolean("byedpi_domain_mixed_case", false),
        hostRemoveSpaces = preferences.getBoolean("byedpi_host_remove_spaces", false),
        tlsRecordSplit = preferences.getBoolean("byedpi_tlsrec_enabled", false),
        tlsRecordSplitPosition = preferences.getString("byedpi_tlsrec_position", null)
            ?.toIntOrNull(),
        tlsRecordSplitAtSni = preferences.getBoolean("byedpi_tlsrec_at_sni", false),
        hostsMode = preferences.getString("byedpi_hosts_mode", null)
            ?.let { HostsMode.fromName(it) },
        hosts = preferences.getString("byedpi_hosts_mode", null)?.let {
            when (HostsMode.fromName(it)) {
                HostsMode.Blacklist -> preferences.getString("byedpi_hosts_blacklist", null)
                HostsMode.Whitelist -> preferences.getString("byedpi_hosts_whitelist", null)
                else -> null
            }
        },
        tcpFastOpen = preferences.getBoolean("byedpi_tcp_fast_open", false),
        udpFakeCount = preferences.getString("byedpi_udp_fake_count", null)?.toIntOrNull(),
        dropSack = preferences.getBoolean("byedpi_drop_sack", false),
        byedpiFakeOffset = preferences.getString("byedpi_fake_offset", null)?.toIntOrNull(),
    )

    /**
     * Converts the UI settings to a byedpi 17.x command line.
     *
     * Groups are separated with `-An`. Whitelist hosts get a leading group without any
     * desync (they bypass it), blacklist hosts limit the desync group to themselves.
     * When every group is limited, the core appends a pass-through group on its own.
     */
    fun toArgs(): Array<String> {
        val args = mutableListOf("ciadpi", "-i", ip, "-p", port.toString())
        args += listOf("-c", maxConnections.toString(), "-b", bufferSize.toString())
        if (customTtl && defaultTtl > 0) args += listOf("-g", defaultTtl.toString())
        if (noDomain) args += "-N"
        if (tcpFastOpen) args += "-F"

        val hostsList = hosts?.split(Regex("\\s+"))?.filter { it.isNotEmpty() }
            ?.joinToString(" ")
            ?.takeIf { it.isNotEmpty() }

        if (hostsMode == HostsMode.Whitelist && hostsList != null) {
            args += listOf("-H", ":$hostsList", "-An")
        }

        val tcpProtocols = buildList {
            if (desyncHttps) add("t")
            if (desyncHttp) add("h")
        }
        // Legacy behaviour: "at host" means SNI as soon as HTTPS is desynced.
        val hostFlag = if (desyncHttps) "+s" else "+h"

        if (tcpProtocols.isNotEmpty() || !desyncUdp) {
            if (tcpProtocols.isNotEmpty()) args += listOf("-K", tcpProtocols.joinToString(","))
            if (hostsMode == HostsMode.Blacklist && hostsList != null) {
                args += listOf("-H", ":$hostsList")
            }

            val splitOption = when (desyncMethod) {
                DesyncMethod.None -> null
                DesyncMethod.Split -> "-s"
                DesyncMethod.Disorder -> "-d"
                DesyncMethod.Fake -> "-f"
                DesyncMethod.OOB -> "-o"
                DesyncMethod.DISOOB -> "-q"
            }
            if (splitOption != null) {
                args += listOf(splitOption, "$splitPosition${if (splitAtHost) hostFlag else ""}")
            }
            if (desyncMethod == DesyncMethod.Fake) {
                args += listOf("-t", fakeTtl.toString())
                if (fakeSni.isNotBlank()) args += listOf("-n", fakeSni.trim())
                if (fakeOffset > 0) args += listOf("-O", fakeOffset.toString())
            }
            if (desyncMethod == DesyncMethod.OOB || desyncMethod == DesyncMethod.DISOOB) {
                val oob = (oobChar.toInt() and 0xFF).toChar()
                args += listOf("-e", if (oob == '\\') "\\\\" else oob.toString())
            }

            val modHttp = buildList {
                if (hostMixedCase) add("h")
                if (domainMixedCase) add("d")
                if (hostRemoveSpaces) add("r")
            }
            if (modHttp.isNotEmpty()) args += listOf("-M", modHttp.joinToString(","))

            if (tlsRecordSplit) {
                args += listOf(
                    "-r",
                    "$tlsRecordSplitPosition${if (tlsRecordSplitAtSni) hostFlag else ""}",
                )
            }
            if (dropSack) args += "-Y"
        }

        if (desyncUdp) {
            if (tcpProtocols.isNotEmpty()) args += "-An"
            args += listOf("-K", "u")
            if (hostsMode == HostsMode.Blacklist && hostsList != null) {
                args += listOf("-H", ":$hostsList")
            }
            if (udpFakeCount > 0) args += listOf("-a", udpFakeCount.toString())
        }

        return args.toTypedArray()
    }

    enum class DesyncMethod {
        None,
        Split,
        Disorder,
        Fake,
        OOB,
        DISOOB;

        companion object {
            fun fromName(name: String): DesyncMethod {
                return when (name) {
                    "none" -> None
                    "split" -> Split
                    "disorder" -> Disorder
                    "fake" -> Fake
                    "oob" -> OOB
                    "disoob" -> DISOOB
                    else -> throw IllegalArgumentException("Unknown desync method: $name")
                }
            }
        }
    }

    enum class HostsMode {
        Disable,
        Blacklist,
        Whitelist;

        companion object {
            fun fromName(name: String): HostsMode {
                return when (name) {
                    "disable" -> Disable
                    "blacklist" -> Blacklist
                    "whitelist" -> Whitelist
                    else -> throw IllegalArgumentException("Unknown hosts mode: $name")
                }
            }
        }
    }
}
