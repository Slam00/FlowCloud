package io.github.dovecoteescapee.byedpi.services

import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.dovecoteescapee.byedpi.data.Mode
import io.github.dovecoteescapee.byedpi.data.AppStatus
import io.github.dovecoteescapee.byedpi.data.START_ACTION
import io.github.dovecoteescapee.byedpi.data.STOP_ACTION
import io.github.dovecoteescapee.byedpi.data.TransportMode

object ServiceManager {
    private val TAG: String = ServiceManager::class.java.simpleName

    fun start(
        context: Context,
        mode: Mode,
        transport: TransportMode = TransportMode.ByeDpi,
    ) {
        setStatus(AppStatus.Connecting, mode)
        try {
        when (mode) {
            Mode.VPN -> {
                activeTransport = transport
                Log.i(TAG, "Starting VPN transport: $transport")
                val intent = Intent(context, ByeDpiVpnService::class.java)
                intent.action = START_ACTION
                intent.putExtra(ByeDpiVpnService.EXTRA_TRANSPORT, transport.name)
                ContextCompat.startForegroundService(context, intent)
            }

            Mode.Proxy -> {
                Log.i(TAG, "Starting proxy")
                val intent = Intent(context, ByeDpiProxyService::class.java)
                intent.action = START_ACTION
                ContextCompat.startForegroundService(context, intent)
            }
        }
        } catch (error: Exception) {
            setStatus(AppStatus.Halted, mode)
            throw error
        }
    }

    fun stop(context: Context) {
        val (_, mode) = appStatus
        setStatus(AppStatus.Disconnecting, mode)
        try {
        when (mode) {
            Mode.VPN -> {
                Log.i(TAG, "Stopping VPN")
                val intent = Intent(context, ByeDpiVpnService::class.java)
                intent.action = STOP_ACTION
                ContextCompat.startForegroundService(context, intent)
            }

            Mode.Proxy -> {
                Log.i(TAG, "Stopping proxy")
                val intent = Intent(context, ByeDpiProxyService::class.java)
                intent.action = STOP_ACTION
                ContextCompat.startForegroundService(context, intent)
            }
        }
        } catch (error: Exception) {
            setStatus(AppStatus.Halted, mode)
            throw error
        }
    }
}
