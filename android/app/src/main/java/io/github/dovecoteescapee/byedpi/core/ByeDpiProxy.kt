package io.github.dovecoteescapee.byedpi.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Runs the bundled byedpi core (ciadpi) in-process.
 *
 * The core is started through its own `main()`, so both settings modes end up as a
 * command line: command-line mode passes the user's arguments as-is and UI mode is
 * converted by [ByeDpiProxyUIPreferences.toArgs].
 */
class ByeDpiProxy {
    companion object {
        init {
            System.loadLibrary("byedpi")
        }

        private const val READY_POLL_INTERVAL_MS = 10L
    }

    /**
     * Blocks until the proxy stops and returns the core's exit code.
     * [onReady] is invoked once the listening socket is up.
     */
    suspend fun startProxy(
        preferences: ByeDpiProxyPreferences,
        onReady: (() -> Unit)? = null,
    ): Int = coroutineScope {
        val args = when (preferences) {
            is ByeDpiProxyCmdPreferences -> preferences.args
            is ByeDpiProxyUIPreferences -> preferences.toArgs()
        }

        val watcher = onReady?.let { callback ->
            launch(Dispatchers.IO) {
                while (isActive && !jniIsListening()) {
                    delay(READY_POLL_INTERVAL_MS)
                }
                if (isActive) callback()
            }
        }

        try {
            withContext(Dispatchers.IO) { jniStartProxy(args) }
        } finally {
            watcher?.cancel()
        }
    }

    /** Asks a running proxy to shut down; returns a negative value if none is listening. */
    fun stopProxy(): Int = jniStopProxy()

    private external fun jniStartProxy(args: Array<String>): Int

    private external fun jniStopProxy(): Int

    private external fun jniIsListening(): Boolean
}
