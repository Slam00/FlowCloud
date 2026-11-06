package io.github.dovecoteescapee.byedpi.core

import java.io.File

/**
 * Extra byedpi 17.x desync groups used by FlowCloud Auto mode.
 *
 * The user's own strategy stays the first group. The groups appended here are
 * only used after byedpi detects that the current one failed for a destination
 * (`-A`: torst = timeout/RST, ssl_err = no ServerHello, redirect = HTTP block
 * page). byedpi then reconnects with the next group while the first request is
 * still buffered, and remembers the working group per IP for [cacheTtlSeconds].
 * Each group dumps its cache to a file on shutdown and reloads it on start, so
 * learned strategies survive network-change restarts and app restarts.
 */
object ByeDpiAutoStrategies {
    const val DEFAULT_CACHE_TTL_SECONDS = 6 * 60 * 60L

    /** TCP_USER_TIMEOUT in seconds; unacknowledged data after this triggers `torst`. */
    private const val TIMEOUT_SECONDS = "4"

    data class Strategy(val name: String, val detect: String, val args: List<String>)

    val strategies: List<Strategy> = listOf(
        Strategy("sni-split", "t,s", listOf("-K", "t", "-s", "1+s", "-d", "3+s", "-r", "1+s")),
        Strategy("fake-ttl", "t,s", listOf("-K", "t", "-f", "1+s", "-t", "6", "-r", "1+s")),
        Strategy("disoob", "t,s", listOf("-K", "t", "-q", "1+s", "-r", "2+s")),
        Strategy("oob-disorder", "t,s", listOf("-K", "t", "-o", "1", "-d", "1+s", "-r", "1+s")),
        Strategy("http-host", "t,r", listOf("-K", "h", "-s", "1+h", "-M", "h,d,r")),
    )

    private val autoOptions = setOf("-A", "--auto")
    private val timeoutOptions = setOf("-T", "--timeout")

    /**
     * Returns [args] with the fallback groups appended, or [args] unchanged if
     * the user already configured auto groups on the command line.
     */
    fun augment(
        args: Array<String>,
        cacheDir: File?,
        cacheTtlSeconds: Long = DEFAULT_CACHE_TTL_SECONDS,
    ): Array<String> {
        if (args.any { arg -> autoOptions.any { arg == it || arg.startsWith("$it=") } }) {
            return args
        }
        val result = args.toMutableList()
        if (args.none { arg -> timeoutOptions.any { arg == it || arg.startsWith("$it=") } }) {
            result += listOf("-T", TIMEOUT_SECONDS)
        }
        strategies.forEachIndexed { index, strategy ->
            result += listOf("-A", strategy.detect)
            result += strategy.args
            result += listOf("-u", cacheTtlSeconds.coerceAtLeast(60).toString())
            if (cacheDir != null) {
                result += listOf("-y", File(cacheDir, cacheFileName(index)).absolutePath)
            }
            result += listOf("--comment", "flowcloud-${strategy.name}")
        }
        return result.toTypedArray()
    }

    fun cacheFileName(index: Int) = "byedpi-auto-$index.cache"

    /** Wraps [preferences] so the core runs with the Auto-mode fallback groups. */
    fun forAutoMode(preferences: ByeDpiProxyPreferences, cacheDir: File?): ByeDpiProxyCmdPreferences {
        val base = when (preferences) {
            is ByeDpiProxyCmdPreferences -> preferences.args
            is ByeDpiProxyUIPreferences -> preferences.toArgs()
        }
        return ByeDpiProxyCmdPreferences(augment(base, cacheDir))
    }
}
