package io.github.dovecoteescapee.byedpi.services

import android.annotation.SuppressLint
import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.LinkProperties
import android.os.Handler
import android.os.Looper
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import androidx.lifecycle.lifecycleScope
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.activities.MainActivity
import io.github.dovecoteescapee.byedpi.core.AutoRouteProxy
import io.github.dovecoteescapee.byedpi.core.AppBypassRepository
import io.github.dovecoteescapee.byedpi.core.BlocklistRepository
import io.github.dovecoteescapee.byedpi.core.ByeDpiProxy
import io.github.dovecoteescapee.byedpi.core.ByeDpiProxyPreferences
import io.github.dovecoteescapee.byedpi.core.DnsOverHttpsProxy
import io.github.dovecoteescapee.byedpi.core.DiagnosticsRepository
import io.github.dovecoteescapee.byedpi.core.TProxyService
import io.github.dovecoteescapee.byedpi.core.WarpRegistrationRepository
import io.github.dovecoteescapee.byedpi.core.SplitTunnelRepository
import io.github.dovecoteescapee.byedpi.data.*
import io.github.dovecoteescapee.byedpi.utility.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

class ByeDpiVpnService : LifecycleVpnService() {
    private val byeDpiProxy = ByeDpiProxy()
    private val autoRouteProxy = AutoRouteProxy()
    private val dnsOverHttpsProxy by lazy { DnsOverHttpsProxy(applicationContext) }
    private var proxyJob: Job? = null
    private var proxyReady = false
    private var autoRouterStarted = false
    private var tunFd: ParcelFileDescriptor? = null
    private var trafficMonitorJob: Job? = null
    private var diagnosticsJob: Job? = null
    private var underlyingNetwork: Network? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var desiredRunning = false
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var networkRecoveryJob: Job? = null
    private var underlyingFingerprint = ""
    private var needsNetworkRecovery = false
    private val mutex = Mutex()
    private var stopping: Boolean = false
    private var selectedTransport = TransportMode.Auto

    companion object {
        private val TAG: String = ByeDpiVpnService::class.java.simpleName
        private const val FOREGROUND_SERVICE_ID: Int = 1
        private const val NOTIFICATION_CHANNEL_ID: String = "ByeDPIVpn"
        private const val MOBILE_IPV6_FIX_KEY = "mobile_ipv6_fix_applied_v027"
        private const val MOBILE_SPLIT_FIX_KEY = "mobile_split_fix_applied_v0210"
        private const val MOBILE_TLS_DESYNC_FIX_KEY = "mobile_tls_desync_fix_applied_v0214"
        const val EXTRA_TRANSPORT = "transport"

        private var status: ServiceStatus = ServiceStatus.Disconnected
    }

    override fun onCreate() {
        super.onCreate()
        registerNotificationChannel(
            this,
            NOTIFICATION_CHANNEL_ID,
            R.string.vpn_channel_name,
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        return when (val action = intent?.action) {
            START_ACTION -> {
                if (desiredRunning) return START_STICKY
                desiredRunning = true
                setStatus(AppStatus.Connecting, Mode.VPN)
                selectedTransport = intent.getStringExtra(EXTRA_TRANSPORT)
                    ?.let { runCatching { TransportMode.valueOf(it) }.getOrNull() }
                    ?: activeTransport
                    ?: TransportMode.Auto
                activeTransport = selectedTransport
                DiagnosticsRepository.beginSession(applicationContext, selectedTransport.name)
                DiagnosticsRepository.append(applicationContext, TAG, "VPN service received START_ACTION")
                startDiagnosticsCollector()
                startForeground()
                acquireWakeLock()
                registerNetworkMonitor()
                lifecycleScope.launch { start() }
                START_STICKY
            }

            STOP_ACTION -> {
                desiredRunning = false
                setStatus(AppStatus.Disconnecting, Mode.VPN)
                unregisterNetworkMonitor()
                lifecycleScope.launch { stop() }
                START_NOT_STICKY
            }

            else -> {
                Log.w(TAG, "Unknown action: $action")
                START_NOT_STICKY
            }
        }
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked")
        desiredRunning = false
        unregisterNetworkMonitor()
        lifecycleScope.launch { stop() }
    }

    override fun onDestroy() {
        desiredRunning = false
        unregisterNetworkMonitor()
        releaseWakeLock()
        super.onDestroy()
    }

    private suspend fun start() {
        Log.i(TAG, "Starting")
        DiagnosticsRepository.append(applicationContext, TAG, "Starting VPN")

        if (status == ServiceStatus.Connected) {
            Log.w(TAG, "VPN already connected")
            return
        }

        try {
            mutex.withLock {
                val preferences = getPreferences()
                applyMobileNetworkCompatibility(preferences)
                val ipv6 = preferences.getBoolean("ipv6_enable", false)
                while (desiredRunning && !bindToUnderlyingNetwork()) {
                    delay(750)
                }
                if (!desiredRunning) return@withLock
                startTransport(ipv6)
            }
            if (!desiredRunning) return
            updateStatus(ServiceStatus.Connected)
            DiagnosticsRepository.append(applicationContext, TAG, "VPN connected")
            startTrafficMonitor()
            scheduleNetworkRecovery()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            drainRouterDiagnostics()
            DiagnosticsRepository.append(applicationContext, TAG, e)
            updateStatus(ServiceStatus.Failed)
            stop()
        }
    }

    private fun startForeground() {
        val notification: Notification = createNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                FOREGROUND_SERVICE_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(FOREGROUND_SERVICE_ID, notification)
        }
    }

    private suspend fun stop() {
        desiredRunning = false
        unregisterNetworkMonitor()
        setStatus(AppStatus.Disconnecting, Mode.VPN)
        Log.i(TAG, "Stopping")
        DiagnosticsRepository.append(applicationContext, TAG, "Stopping VPN")

        mutex.withLock {
            stopping = true
            try {
                withContext(Dispatchers.IO) {
                    stopTrafficMonitor()
                    // Close the SOCKS destination first so active tun2socks sessions
                    // leave their reads before the native worker is joined.
                    runCatching { stopAutoRouter() }
                        .onFailure { Log.e(TAG, "Failed to stop router", it) }
                    runCatching { stopTun2Socks() }
                        .onFailure { Log.e(TAG, "Failed to stop tun2socks", it) }
                    runCatching { stopDnsRelay() }
                        .onFailure { Log.e(TAG, "Failed to stop DNS relay", it) }
                }
                runCatching { stopProxy() }
                    .onFailure { Log.e(TAG, "Failed to stop ByeDPI", it) }
                unbindUnderlyingNetwork()
            } finally {
                stopping = false
                releaseWakeLock()
            }
        }

        drainRouterDiagnostics()
        DiagnosticsRepository.append(applicationContext, TAG, "VPN stopped")
        updateStatus(ServiceStatus.Disconnected)
        activeTransport = null
        stopSelf()
    }

    private suspend fun startProxy() {
        Log.i(TAG, "Starting proxy")

        if (proxyJob != null) {
            Log.w(TAG, "Proxy fields not null")
            throw IllegalStateException("Proxy fields not null")
        }

        val preferences = getByeDpiPreferences()

        val ready = CompletableDeferred<Unit>()
        proxyJob = lifecycleScope.launch(Dispatchers.IO) {
            val code = try {
                byeDpiProxy.startProxy(preferences) {
                    proxyReady = true
                    ready.complete(Unit)
                }
            } catch (error: Throwable) {
                if (!ready.isCompleted) ready.completeExceptionally(error)
                throw error
            }
            if (!ready.isCompleted) {
                ready.completeExceptionally(IllegalStateException("ByeDPI failed with code $code"))
            }

            withContext(Dispatchers.Main) {
                if (code != 0) {
                    Log.e(TAG, "Proxy stopped with code $code")
                    updateStatus(ServiceStatus.Failed)
                } else {
                    if (!stopping) {
                        lifecycleScope.launch { stop() }
                    }
                }
            }
        }

        ready.await()

        Log.i(TAG, "Proxy started")
    }

    private suspend fun stopProxy() {
        Log.i(TAG, "Stopping proxy")

        if (proxyJob == null) {
            Log.w(TAG, "Proxy already disconnected")
            return
        }

        try {
            if (proxyReady) {
                byeDpiProxy.stopProxy()
            }
            proxyJob?.join()
        } finally {
            proxyJob = null
            proxyReady = false
        }

        Log.i(TAG, "Proxy stopped")
    }

    private fun startDnsRelay(ipv6: Boolean): String = runCatching {
        dnsOverHttpsProxy.start(ipv6)
    }.onFailure {
        Log.w(TAG, "Encrypted DNS relay is unavailable; using transport fallback", it)
    }.getOrDefault("")

    private fun stopDnsRelay() {
        dnsOverHttpsProxy.stop()
    }

    private suspend fun startAutoRouter(byeDpiPort: Int, dnsRelayAddress: String): Int {
        val routerPort = if (byeDpiPort == 1081) 1082 else 1081
        val blocklists = BlocklistRepository(applicationContext)
        val warpConfigJson = withContext(Dispatchers.IO) {
            if (selectedTransport == TransportMode.ByeDpi) {
                ""
            } else {
                val registration = runCatching {
                    WarpRegistrationRepository(applicationContext)
                        .getOrRegister(byeDpiPort)
                        .toRouterJson()
                }
                registration.onFailure {
                    Log.w(TAG, "WARP registration is unavailable; using ByeDPI fallback", it)
                }
                if (selectedTransport == TransportMode.Warp) {
                    registration.getOrThrow()
                } else {
                    registration.getOrDefault("")
                }
            }
        }
        val warpRules = when (selectedTransport) {
            TransportMode.ByeDpi -> ""
            TransportMode.Warp -> "*"
            TransportMode.Auto -> listOf(
                blocklists.warpRoutingRules(),
                SplitTunnelRepository(applicationContext).load().asRouterRules(),
            ).joinToString("\n")
        }
        val byeDpiRules = when (selectedTransport) {
            TransportMode.ByeDpi,
            TransportMode.Warp -> ""
            TransportMode.Auto -> blocklists.byeDpiRoutingRules()
        }
        withContext(Dispatchers.IO) {
            DiagnosticsRepository.append(
                applicationContext,
                TAG,
                "Starting route engine: mode=$selectedTransport, DNS relay=${dnsRelayAddress.ifBlank { "unavailable" }}",
            )
            autoRouteProxy.start(
                listenAddress = "127.0.0.1:$routerPort",
                byeDpiAddress = "127.0.0.1:$byeDpiPort",
                dnsRelayAddress = dnsRelayAddress,
                warpRules = warpRules,
                byeDpiRules = byeDpiRules,
                warpConfig = warpConfigJson,
            )
        }
        autoRouterStarted = true
        drainRouterDiagnostics()
        return routerPort
    }

    private fun stopAutoRouter() {
        if (autoRouterStarted) {
            autoRouteProxy.stop()
            autoRouterStarted = false
        }
    }

    private fun startTun2Socks(port: Int, ipv6: Boolean) {
        Log.i(TAG, "Starting tun2socks")

        val sharedPreferences = getPreferences()
        val dns = sharedPreferences.getStringNotNull("dns_ip", "1.1.1.1")

        val tun2socksConfig = """
        | misc:
        |   task-stack-size: 86016
        |   log-file: stderr
        |   log-level: info
        | socks5:
        |   mtu: 8500
        |   address: 127.0.0.1
        |   port: $port
        |   udp: udp
        """.trimMargin("| ")

        val configPath = try {
            File.createTempFile("config", "tmp", cacheDir).apply {
                writeText(tun2socksConfig)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create config file", e)
            throw e
        }

        val existingFd = tunFd
        val fd = existingFd ?: createBuilder(dns, ipv6).establish()
            ?: throw IllegalStateException("VPN connection failed")

        this.tunFd = fd

        if (!TProxyService.TProxyStartService(configPath.absolutePath, fd.fd)) {
            if (existingFd == null) {
                tunFd = null
                fd.close()
            }
            throw IllegalStateException("Tun2Socks worker did not start")
        }
        Thread.sleep(75)
        if (!TProxyService.TProxyIsRunning()) {
            if (existingFd == null) {
                tunFd = null
                fd.close()
            }
            throw IllegalStateException("Tun2Socks stopped while reading its configuration")
        }

        Log.i(TAG, "Tun2Socks started")
    }

    private fun chooseUnderlyingNetwork(): Network? {
        val connectivityManager = getSystemService(ConnectivityManager::class.java)
        val candidates = connectivityManager.allNetworks.filter { network ->
            val capabilities = connectivityManager.getNetworkCapabilities(network)
                ?: return@filter false
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED))
        }
        return candidates.maxByOrNull { network ->
            val caps = connectivityManager.getNetworkCapabilities(network)
            (if (caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true) 100 else 0) +
                (when {
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> 30
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> 20
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 10
                    else -> 0
                }) + (if (network == underlyingNetwork) 1 else 0)
        }
    }

    private fun networkFingerprint(network: Network): String {
        val properties = getSystemService(ConnectivityManager::class.java)
            .getLinkProperties(network) ?: return ""
        return listOf(
            properties.interfaceName.orEmpty(),
            properties.linkAddresses.map { it.toString() }.sorted().joinToString(),
            properties.routes.map { it.toString() }.sorted().joinToString(),
            properties.dnsServers.map { it.hostAddress }.sortedBy { it }.joinToString(),
        ).joinToString("|")
    }

    private fun bindToUnderlyingNetwork(network: Network? = chooseUnderlyingNetwork()): Boolean {
        val connectivityManager = getSystemService(ConnectivityManager::class.java)

        if (network == null) {
            Log.w(TAG, "No physical underlying network is available")
            underlyingNetwork = null
            return false
        }

        if (connectivityManager.bindProcessToNetwork(network)) {
            underlyingNetwork = network
            underlyingFingerprint = networkFingerprint(network)
            val capabilities = connectivityManager.getNetworkCapabilities(network)
            val transport = when {
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ethernet"
                else -> "other"
            }
            Log.i(TAG, "Proxy process bound to physical $transport network $network")
            DiagnosticsRepository.append(
                applicationContext,
                TAG,
                "Bound to physical $transport network; validated=" +
                    (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true),
            )
        } else {
            underlyingNetwork = null
            Log.w(TAG, "Android rejected binding to physical network $network")
            DiagnosticsRepository.append(applicationContext, TAG, "Android rejected physical network binding")
            return false
        }
        return true
    }

    private fun registerNetworkMonitor() {
        if (networkCallback != null) return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = onPhysicalNetworkEvent()
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) =
                onPhysicalNetworkEvent()
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) =
                onPhysicalNetworkEvent()
            override fun onLost(network: Network) {
                onPhysicalNetworkEvent(network)
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val connectivity = getSystemService(ConnectivityManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            connectivity.registerNetworkCallback(request, callback, Handler(Looper.getMainLooper()))
        } else {
            connectivity.registerNetworkCallback(request, callback)
        }
        networkCallback = callback
    }

    private fun onPhysicalNetworkEvent(lostNetwork: Network? = null) {
        lifecycleScope.launch {
            if (!desiredRunning) return@launch
            if (lostNetwork != null) {
                DiagnosticsRepository.append(applicationContext, TAG, "Physical network lost: $lostNetwork")
                if (lostNetwork == underlyingNetwork) needsNetworkRecovery = true
            }
            scheduleNetworkRecovery()
        }
    }

    private fun unregisterNetworkMonitor() {
        networkCallback?.let {
            runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
                .onFailure { error -> Log.w(TAG, "Cannot unregister network monitor", error) }
        }
        networkCallback = null
    }

    private fun scheduleNetworkRecovery() {
        if (!desiredRunning || networkRecoveryJob?.isActive == true) return
        networkRecoveryJob = lifecycleScope.launch {
            // Coalesce roaming callbacks; the same Wi-Fi Network/IP needs no restart.
            delay(750)
            while (desiredRunning) {
                if (tunFd == null) return@launch
                val candidate = chooseUnderlyingNetwork()
                if (candidate == null) {
                    needsNetworkRecovery = true
                    setStatus(AppStatus.Reconnecting, Mode.VPN)
                    setUnderlyingNetworks(emptyArray())
                    getSystemService(ConnectivityManager::class.java).bindProcessToNetwork(null)
                    delay(1_000)
                    continue
                }
                if (!needsNetworkRecovery && candidate == underlyingNetwork &&
                    networkFingerprint(candidate) == underlyingFingerprint) return@launch
                setStatus(AppStatus.Reconnecting, Mode.VPN)
                try {
                    mutex.withLock {
                        if (!desiredRunning) return@withLock
                        DiagnosticsRepository.append(applicationContext, TAG,
                            "Recovering transport: network $underlyingNetwork -> $candidate; keeping VPN interface")
                        stopping = true
                        try {
                            stopTransportForRecovery()
                            if (!desiredRunning) return@withLock
                            check(bindToUnderlyingNetwork(candidate)) { "Cannot bind to replacement network" }
                            check(setUnderlyingNetworks(arrayOf(candidate))) { "Cannot update VPN underlying network" }
                            startTransport(getPreferences().getBoolean("ipv6_enable", false))
                            needsNetworkRecovery = false
                        } finally {
                            stopping = false
                        }
                    }
                    if (!desiredRunning) return@launch
                    // A second switch may have arrived while WARP was being started.
                    if (candidate == chooseUnderlyingNetwork() &&
                        networkFingerprint(candidate) == underlyingFingerprint && !needsNetworkRecovery) {
                        setStatus(AppStatus.Running, Mode.VPN)
                        DiagnosticsRepository.append(applicationContext, TAG,
                            "Transport recovered on network $candidate")
                    }
                } catch (error: Exception) {
                    needsNetworkRecovery = true
                    DiagnosticsRepository.append(applicationContext, TAG, error)
                    Log.w(TAG, "Network recovery failed; retrying", error)
                    delay(3_000)
                }
                delay(750)
            }
        }
    }

    private suspend fun startTransport(ipv6: Boolean) {
        startProxy()
        val byeDpiPort = getPreferences().getString("byedpi_proxy_port", null)?.toIntOrNull() ?: 1080
        val port = if (selectedTransport == TransportMode.ByeDpi) byeDpiPort else {
            val dnsRelayAddress = withContext(Dispatchers.IO) { startDnsRelay(ipv6) }
            startAutoRouter(byeDpiPort, dnsRelayAddress)
        }
        withContext(Dispatchers.IO) { startTun2Socks(port, ipv6) }
    }

    private suspend fun stopTransportForRecovery() {
        withContext(Dispatchers.IO) {
            stopAutoRouter()
            stopTun2Socks(closeInterface = false)
            stopDnsRelay()
        }
        stopProxy()
    }

    private fun unbindUnderlyingNetwork() {
        val connectivityManager = getSystemService(ConnectivityManager::class.java)
        if (!connectivityManager.bindProcessToNetwork(null)) {
            Log.w(TAG, "Android rejected clearing the physical network binding")
        }
        underlyingNetwork = null
    }

    @SuppressLint("WakelockTimeout")
    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        wakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$packageName:FlowCloudVpn")
            .apply {
                setReferenceCounted(false)
                acquire()
            }
        Log.i(TAG, "VPN CPU wake lock acquired")
        DiagnosticsRepository.append(applicationContext, TAG, "VPN CPU wake lock acquired")
    }

    private fun releaseWakeLock() {
        wakeLock?.let { lock ->
            if (lock.isHeld) lock.release()
        }
        if (wakeLock != null) {
            Log.i(TAG, "VPN CPU wake lock released")
            DiagnosticsRepository.append(applicationContext, TAG, "VPN CPU wake lock released")
        }
        wakeLock = null
    }

    private fun startTrafficMonitor() {
        trafficMonitorJob?.cancel()
        trafficMonitorJob = lifecycleScope.launch(Dispatchers.IO) {
            while (isActive && tunFd != null) {
                delay(5_000)
                val stats = runCatching { TProxyService.TProxyGetStats() }
                    .onFailure { Log.w(TAG, "Cannot read tunnel traffic counters", it) }
                    .getOrNull()
                    ?: continue
                if (stats.size >= 4) {
                    Log.i(
                        TAG,
                        "Tunnel traffic: tx=${stats[0]} packets/${stats[1]} bytes, " +
                            "rx=${stats[2]} packets/${stats[3]} bytes",
                    )
                }
            }
        }
    }

    private fun stopTrafficMonitor() {
        trafficMonitorJob?.cancel()
        trafficMonitorJob = null
    }

    private fun startDiagnosticsCollector() {
        diagnosticsJob?.cancel()
        diagnosticsJob = lifecycleScope.launch(Dispatchers.IO) {
            while (isActive) {
                drainRouterDiagnostics()
                delay(250)
            }
        }
    }

    private fun drainRouterDiagnostics() {
        runCatching { autoRouteProxy.drainDiagnostics() }
            .onFailure { Log.w(TAG, "Cannot drain native diagnostics", it) }
            .getOrDefault("")
            .takeIf { it.isNotBlank() }
            ?.let { DiagnosticsRepository.append(applicationContext, "Native", it) }
    }

    private fun applyMobileNetworkCompatibility(
        preferences: android.content.SharedPreferences,
    ) {
        val editor = preferences.edit()
        var changed = false
        if (!preferences.getBoolean(MOBILE_IPV6_FIX_KEY, false)) {
            editor.putBoolean("ipv6_enable", false)
                .putBoolean(MOBILE_IPV6_FIX_KEY, true)
            changed = true
            Log.i(TAG, "IPv6 disabled for mobile network compatibility")
        }
        if (!preferences.getBoolean(MOBILE_SPLIT_FIX_KEY, false)) {
            val method = preferences.getString("byedpi_desync_method", null)
            if (!preferences.getBoolean("byedpi_enable_cmd_settings", false) &&
                (method == null || method == "disorder")
            ) {
                editor.putString("byedpi_desync_method", "split")
                Log.i(TAG, "ByeDPI strategy changed from disorder to mobile-compatible split")
            }
            editor.putBoolean(MOBILE_SPLIT_FIX_KEY, true)
            changed = true
        }
        if (!preferences.getBoolean(MOBILE_TLS_DESYNC_FIX_KEY, false)) {
            if (!preferences.getBoolean("byedpi_enable_cmd_settings", false)) {
                editor
                    .putString("byedpi_desync_method", "disorder")
                    .putString("byedpi_split_position", "1")
                    .putBoolean("byedpi_tlsrec_enabled", true)
                    .putString("byedpi_tlsrec_position", "1")
                    .putBoolean("byedpi_tlsrec_at_sni", true)
                Log.i(TAG, "Enabled mobile TLS desync profile: disorder + TLS record split")
            }
            editor.putBoolean(MOBILE_TLS_DESYNC_FIX_KEY, true)
            changed = true
        }
        if (changed) editor.apply()
    }

    private fun stopTun2Socks(closeInterface: Boolean = true) {
        Log.i(TAG, "Stopping tun2socks")

        if (tunFd == null) {
            return
        }
        if (!TProxyService.TProxyStopService()) {
            Log.w(TAG, "Tun2Socks worker reported a stop failure")
        }

        try {
            File(cacheDir, "config.tmp").delete()
        } catch (e: SecurityException) {
            Log.e(TAG, "Failed to delete config file", e)
        }

        if (closeInterface) {
            tunFd?.close() ?: Log.w(TAG, "VPN not running")
            tunFd = null
        }

        Log.i(TAG, "Tun2socks stopped")
    }

    private fun getByeDpiPreferences(): ByeDpiProxyPreferences =
        ByeDpiProxyPreferences.fromSharedPreferences(getPreferences())

    private fun updateStatus(newStatus: ServiceStatus) {
        Log.d(TAG, "VPN status changed from $status to $newStatus")

        status = newStatus

        setStatus(
            when (newStatus) {
                ServiceStatus.Connected -> AppStatus.Running

                ServiceStatus.Disconnected,
                ServiceStatus.Failed -> AppStatus.Halted
            },
            Mode.VPN
        )

        val intent = Intent(
            when (newStatus) {
                ServiceStatus.Connected -> STARTED_BROADCAST
                ServiceStatus.Disconnected -> STOPPED_BROADCAST
                ServiceStatus.Failed -> FAILED_BROADCAST
            }
        ).setPackage(packageName)
        intent.putExtra(SENDER, Sender.VPN.ordinal)
        sendBroadcast(intent)
    }

    private fun createNotification(): Notification =
        createConnectionNotification(
            this,
            NOTIFICATION_CHANNEL_ID,
            R.string.notification_title,
            when (selectedTransport) {
                TransportMode.Auto -> R.string.auto_notification_content
                TransportMode.ByeDpi -> R.string.vpn_notification_content
                TransportMode.Warp -> R.string.warp_notification_content
            },
            ByeDpiVpnService::class.java,
        )

    private fun createBuilder(dns: String, ipv6: Boolean): Builder {
        Log.d(TAG, "DNS: $dns")
        val builder = Builder()
        builder.setSession(
            when (selectedTransport) {
                TransportMode.Auto -> "FlowCloud Auto"
                TransportMode.ByeDpi -> "ByeDPI"
                TransportMode.Warp -> "FlowCloud WARP"
            }
        )
        builder.setConfigureIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE,
            )
        )

        builder.addAddress("10.10.10.10", 32)
            .addRoute("0.0.0.0", 0)
            .setBlocking(false)

        builder.setUnderlyingNetworks(underlyingNetwork?.let { arrayOf(it) })

        if (selectedTransport != TransportMode.ByeDpi) {
            builder.setMtu(1280)
        }

        if (ipv6) {
            builder.addAddress("fd00::1", 128)
                .addRoute("::", 0)
        }

        if (dns.isNotBlank()) {
            builder.addDnsServer(dns)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        builder.addDisallowedApplication(applicationContext.packageName)
        AppBypassRepository(applicationContext).load().forEach { packageName ->
            runCatching { builder.addDisallowedApplication(packageName) }
                .onFailure { error ->
                    Log.w(TAG, "Cannot exclude $packageName from VPN", error)
                }
        }

        return builder
    }
}
