package io.github.dovecoteescapee.byedpi.services

import io.github.dovecoteescapee.byedpi.data.AppStatus
import io.github.dovecoteescapee.byedpi.data.Mode
import io.github.dovecoteescapee.byedpi.data.TransportMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

private val mutableConnectionStatus = MutableStateFlow(AppStatus.Halted to Mode.VPN)
val connectionStatus = mutableConnectionStatus.asStateFlow()
val appStatus: Pair<AppStatus, Mode>
    get() = connectionStatus.value

fun setStatus(status: AppStatus, mode: Mode) {
    mutableConnectionStatus.value = status to mode
}

var activeTransport: TransportMode? = null
