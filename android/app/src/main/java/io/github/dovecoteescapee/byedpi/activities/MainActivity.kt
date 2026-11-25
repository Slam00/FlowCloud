package io.github.dovecoteescapee.byedpi.activities

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import io.github.dovecoteescapee.byedpi.BuildConfig
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.core.AppRelease
import io.github.dovecoteescapee.byedpi.core.AppBypassRepository
import io.github.dovecoteescapee.byedpi.core.AutoRouteProxy
import io.github.dovecoteescapee.byedpi.core.WarpRouteInfo
import io.github.dovecoteescapee.byedpi.services.activeTransport
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import io.github.dovecoteescapee.byedpi.core.AppUpdateRepository
import io.github.dovecoteescapee.byedpi.core.BlocklistRepository
import io.github.dovecoteescapee.byedpi.core.DiagnosticsRepository
import io.github.dovecoteescapee.byedpi.core.SplitTunnelRepository
import io.github.dovecoteescapee.byedpi.core.UpdateCheckResult
import io.github.dovecoteescapee.byedpi.core.UpdateVerificationException
import io.github.dovecoteescapee.byedpi.data.*
import io.github.dovecoteescapee.byedpi.fragments.MainSettingsFragment
import io.github.dovecoteescapee.byedpi.databinding.ActivityMainBinding
import io.github.dovecoteescapee.byedpi.services.ServiceManager
import io.github.dovecoteescapee.byedpi.services.appStatus
import io.github.dovecoteescapee.byedpi.services.connectionStatus
import io.github.dovecoteescapee.byedpi.services.setStatus
import io.github.dovecoteescapee.byedpi.utility.*
import io.github.dovecoteescapee.byedpi.views.ConnectionRingView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var blocklists: BlocklistRepository
    private lateinit var splitTunnel: SplitTunnelRepository
    private lateinit var appBypass: AppBypassRepository
    private lateinit var appUpdates: AppUpdateRepository
    private var pendingTransport = TransportMode.Auto
    private var currentTransport = TransportMode.Auto
    private val warpRoute by lazy { AutoRouteProxy() }
    private var updateDialog: androidx.appcompat.app.AlertDialog? = null
    private var pendingUpdateFile: File? = null
    private var updateWorkRunning = false

    companion object {
        private val TAG: String = MainActivity::class.java.simpleName
        private const val AUTOMATIC_UPDATES_KEY = "automatic_update_checks"
        private const val PENDING_UPDATE_PATH = "pending_update_path"
        private const val WARP_PING_INTERVAL_MS = 5_000L

        private fun collectLogs(context: Context): String? =
            try {
                val logcat = Runtime.getRuntime()
                    .exec("logcat *:D -d")
                    .inputStream.bufferedReader()
                    .use { it.readText() }
                buildString {
                    appendLine("--- FlowCloud internal diagnostics ---")
                    append(DiagnosticsRepository.read(context))
                    appendLine()
                    appendLine("--- Android logcat ---")
                    if (logcat.isBlank()) appendLine("logcat is unavailable on this device.")
                    else append(logcat)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to collect logs", e)
                null
            }
    }

    private val vpnRegister =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == RESULT_OK) {
                ServiceManager.start(this, Mode.VPN, pendingTransport)
            } else {
                DiagnosticsRepository.append(
                    applicationContext,
                    TAG,
                    "Android VPN permission was not granted",
                )
                Toast.makeText(this, R.string.vpn_permission_denied, Toast.LENGTH_SHORT).show()
                setStatus(AppStatus.Halted, Mode.VPN)
                updateStatus()
            }
        }

    private val logsRegister =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            lifecycleScope.launch(Dispatchers.IO) {
                val logs = collectLogs(this@MainActivity)

                if (logs == null) {
                    Toast.makeText(
                        this@MainActivity,
                        R.string.logs_failed,
                        Toast.LENGTH_SHORT
                    ).show()
                } else {
                    val uri = it.data?.data ?: run {
                        Log.e(TAG, "No data in result")
                        return@launch
                    }
                    contentResolver.openOutputStream(uri)?.use {
                        try {
                            it.write(logs.toByteArray())
                        } catch (e: IOException) {
                            Log.e(TAG, "Failed to save logs", e)
                        }
                    } ?: run {
                        Log.e(TAG, "Failed to open output stream")
                    }
                }
            }
        }

    private val updateInstallPermissionRegister =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            val update = pendingUpdateFile
            pendingUpdateFile = null
            if (update != null &&
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
                    packageManager.canRequestPackageInstalls())
            ) {
                openPackageInstaller(update)
            } else {
                Toast.makeText(this, R.string.install_permission_denied, Toast.LENGTH_LONG).show()
            }
        }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            Log.d(TAG, "Received intent: ${intent?.action}")

            if (intent == null) {
                Log.w(TAG, "Received null intent")
                return
            }

            val senderOrd = intent.getIntExtra(SENDER, -1)
            val sender = Sender.entries.getOrNull(senderOrd)
            if (sender == null) {
                Log.w(TAG, "Received intent with unknown sender: $senderOrd")
                return
            }

            when (val action = intent.action) {
                STARTED_BROADCAST,
                STOPPED_BROADCAST -> updateStatus()

                FAILED_BROADCAST -> {
                    Toast.makeText(
                        context,
                        getString(R.string.failed_to_start, sender.name),
                        Toast.LENGTH_SHORT,
                    ).show()
                    updateStatus()
                }

                else -> Log.w(TAG, "Unknown action: $action")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        val preferences = getPreferences()
        if (!preferences.getBoolean("dark_theme_default_applied", false)) {
            val previousTheme = preferences.getString("app_theme", null)
            preferences.edit()
                .apply {
                    if (previousTheme == null || previousTheme == "system") {
                        putString("app_theme", "dark")
                    }
                }
                .putBoolean("dark_theme_default_applied", true)
                .apply()
        }

        val selectedTheme = preferences.getString("app_theme", null) ?: "dark"
        MainSettingsFragment.setTheme(selectedTheme)
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applySystemBarAppearance()
        blocklists = BlocklistRepository(applicationContext)
        splitTunnel = SplitTunnelRepository(applicationContext)
        appBypass = AppBypassRepository(applicationContext)
        appUpdates = AppUpdateRepository(applicationContext)
        pendingUpdateFile = savedInstanceState?.getString(PENDING_UPDATE_PATH)?.let(::File)

        val intentFilter = IntentFilter().apply {
            addAction(STARTED_BROADCAST)
            addAction(STOPPED_BROADCAST)
            addAction(FAILED_BROADCAST)
        }

        @SuppressLint("UnspecifiedRegisterReceiverFlag")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, intentFilter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(receiver, intentFilter)
        }

        binding.statusButton.setOnClickListener {
            val (status, _) = appStatus
            when (status) {
                AppStatus.Halted -> start()
                AppStatus.Running -> stop()
                AppStatus.Reconnecting -> stop()
                AppStatus.Connecting -> stop()
                AppStatus.Disconnecting -> Unit
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                connectionStatus.collect { updateStatus() }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                connectionStatus.collectLatest { (status, mode) -> followWarpInfo(status, mode) }
            }
        }

        binding.bottomNavigation.setOnItemSelectedListener { item ->
            val showSettings = item.itemId == R.id.navigation_settings
            binding.homePage.visibility = if (showSettings) View.GONE else View.VISIBLE
            binding.settingsPage.visibility = if (showSettings) View.VISIBLE else View.GONE
            true
        }

        val savedRules = splitTunnel.load()
        binding.domainRulesInput.setText(savedRules.domainsText())
        binding.networkRulesInput.setText(savedRules.networksText())
        binding.routingRulesStatus.text = getString(
            R.string.split_rules_saved,
            savedRules.domains.size,
            savedRules.networks.size,
        )
        binding.saveRoutingRulesButton.setOnClickListener { saveSplitTunnelRules() }
        updateExcludedAppsStatus()
        binding.selectExcludedAppsButton.setOnClickListener { showAppBypassDialog() }
        binding.advancedSettingsButton.setOnClickListener { openAdvancedSettings() }
        binding.saveLogsButton.setOnClickListener { launchLogExport() }
        binding.updateStatus.text = getString(
            R.string.installed_version,
            BuildConfig.VERSION_NAME.removeSuffix("-debug"),
        )
        binding.automaticUpdatesSwitch.isChecked =
            preferences.getBoolean(AUTOMATIC_UPDATES_KEY, true)
        binding.automaticUpdatesSwitch.setOnCheckedChangeListener { _, enabled ->
            preferences.edit().putBoolean(AUTOMATIC_UPDATES_KEY, enabled).apply()
            if (enabled) checkForUpdates(manual = false, force = true)
        }
        binding.checkUpdatesButton.setOnClickListener {
            checkForUpdates(manual = true, force = true)
        }

        currentTransport = preferences.transportMode()
        val transportOptions = TransportOption.all(this)
        binding.transportDropdown.setAdapter(TransportModeAdapter(this, transportOptions))
        binding.transportDropdown.setText(getString(TransportOption.titleRes(currentTransport)), false)
        binding.transportDropdown.setOnItemClickListener { _, _, position, _ ->
            val mode = transportOptions[position].mode
            if (mode != currentTransport) {
                currentTransport = mode
                preferences.saveTransportMode(mode)
            }
            updateDecision()
            updateStatus()
        }
        updateDecision()
        lifecycleScope.launch {
            runCatching { blocklists.updateIfNeeded() }
                .onSuccess { updateDecision() }
                .onFailure { Log.w(TAG, "Blocklist update failed; using bundled lists", it) }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
        // Also when the app returns from the background: the activity is often
        // kept alive, so a check only in onCreate would rarely run.
        if (binding.automaticUpdatesSwitch.isChecked && updateDialog?.isShowing != true) {
            checkForUpdates(manual = false, force = false)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(receiver)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        pendingUpdateFile?.let { outState.putString(PENDING_UPDATE_PATH, it.absolutePath) }
        super.onSaveInstanceState(outState)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val (status, _) = appStatus

        return when (item.itemId) {
            R.id.action_settings -> {
                if (status == AppStatus.Halted) {
                    openAdvancedSettings()
                } else {
                    Toast.makeText(this, R.string.settings_unavailable, Toast.LENGTH_SHORT)
                        .show()
                }
                true
            }

            R.id.action_save_logs -> {
                launchLogExport()
                true
            }

            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun start() {
        pendingTransport = selectedTransport()
        setStatus(AppStatus.Connecting, Mode.VPN)
        updateStatus()
        DiagnosticsRepository.append(
            applicationContext,
            TAG,
            "Connect button pressed: mode=${pendingTransport.name}",
        )
        val intentPrepare = VpnService.prepare(this)
        if (intentPrepare != null) {
            vpnRegister.launch(intentPrepare)
        } else {
            ServiceManager.start(this, Mode.VPN, pendingTransport)
        }
    }

    private fun stop() {
        ServiceManager.stop(this)
    }

    /**
     * Shows the WARP endpoint and the ping through it while the VPN runs in WARP
     * mode. Cancelled and restarted by collectLatest on every status change.
     */
    private suspend fun followWarpInfo(status: AppStatus, mode: Mode) {
        val transport = activeTransport
        val shown = status == AppStatus.Running && mode == Mode.VPN &&
            (transport == TransportMode.Warp || transport == TransportMode.Auto)
        if (!shown) {
            binding.warpInfo.visibility = View.GONE
            return
        }
        binding.warpInfo.visibility = View.VISIBLE
        renderWarpInfo(withContext(Dispatchers.IO) { warpRoute.warpInfo(measurePing = false) }, measuring = true)
        while (true) {
            renderWarpInfo(withContext(Dispatchers.IO) { warpRoute.warpInfo(measurePing = true) }, measuring = false)
            delay(WARP_PING_INTERVAL_MS)
        }
    }

    private fun renderWarpInfo(info: WarpRouteInfo, measuring: Boolean) {
        if (info.state == "unavailable") {
            // Auto mode without a WARP profile: there is nothing to show.
            binding.warpInfo.visibility = View.GONE
            return
        }
        binding.warpInfo.visibility = View.VISIBLE
        if (info.endpoint.isBlank()) {
            binding.warpInfoPing.visibility = View.GONE
            if (info.state == "failed") {
                binding.warpInfoLabel.setText(R.string.warp_info_server)
                binding.warpInfoEndpoint.visibility = View.VISIBLE
                binding.warpInfoEndpoint.setText(
                    if (activeTransport == TransportMode.Auto) R.string.warp_info_failed_auto
                    else R.string.warp_info_failed,
                )
                binding.warpInfoEndpoint.setTextColor(ContextCompat.getColor(this, R.color.flow_text_secondary))
            } else {
                binding.warpInfoLabel.setText(R.string.warp_info_searching)
                binding.warpInfoEndpoint.visibility = View.GONE
            }
            return
        }
        binding.warpInfoEndpoint.setTextColor(ContextCompat.getColor(this, R.color.flow_text))
        binding.warpInfoLabel.text = getString(R.string.warp_info_label, info.transport)
        binding.warpInfoEndpoint.visibility = View.VISIBLE
        binding.warpInfoEndpoint.text = info.endpoint
        binding.warpInfoPing.visibility = View.VISIBLE
        val (text, color) = when {
            measuring -> getString(R.string.warp_info_ping_measuring) to R.color.flow_text_secondary
            info.pingMs < 0 -> getString(R.string.warp_info_ping_failed) to R.color.flow_ping_bad
            else -> getString(R.string.warp_info_ping, info.pingMs) to when {
                info.pingMs < 120 -> R.color.flow_connected
                info.pingMs < 300 -> R.color.flow_reconnecting
                else -> R.color.flow_ping_bad
            }
        }
        binding.warpInfoPing.text = text
        binding.warpInfoPing.setTextColor(ContextCompat.getColor(this, color))
    }

    private fun updateStatus() {
        val (status, mode) = appStatus

        Log.i(TAG, "Updating status: $status, $mode")
        renderConnectionState(status)
        val canEdit = status == AppStatus.Halted
        binding.transportLayout.isEnabled = canEdit
        binding.transportLayout.alpha = if (canEdit) 1f else 0.5f
        if (!canEdit) binding.transportDropdown.dismissDropDown()

        when (status) {
            AppStatus.Halted -> {
                binding.statusButton.isEnabled = true
                binding.domainRulesInput.isEnabled = true
                binding.networkRulesInput.isEnabled = true
                binding.saveRoutingRulesButton.isEnabled = true
                binding.selectExcludedAppsButton.isEnabled = true
                val rules = splitTunnel.load()
                binding.routingRulesStatus.text = getString(
                    R.string.split_rules_saved,
                    rules.domains.size,
                    rules.networks.size,
                )
            }

            AppStatus.Running -> {
                binding.statusButton.isEnabled = true
                binding.domainRulesInput.isEnabled = false
                binding.networkRulesInput.isEnabled = false
                binding.saveRoutingRulesButton.isEnabled = false
                binding.selectExcludedAppsButton.isEnabled = false
                binding.routingRulesStatus.setText(R.string.split_rules_locked)
            }
            AppStatus.Connecting,
            AppStatus.Reconnecting,
            AppStatus.Disconnecting -> {
                binding.statusButton.isEnabled = status != AppStatus.Disconnecting
                binding.domainRulesInput.isEnabled = false
                binding.networkRulesInput.isEnabled = false
                binding.saveRoutingRulesButton.isEnabled = false
                binding.selectExcludedAppsButton.isEnabled = false
                binding.routingRulesStatus.setText(R.string.split_rules_locked)
            }
        }
    }

    /** Ring, button label/colour and the status headline for the current connection state. */
    private fun renderConnectionState(status: AppStatus) {
        val ringState = when (status) {
            AppStatus.Halted -> ConnectionRingView.State.Halted
            AppStatus.Connecting -> ConnectionRingView.State.Connecting
            AppStatus.Running -> ConnectionRingView.State.Running
            AppStatus.Reconnecting -> ConnectionRingView.State.Reconnecting
            AppStatus.Disconnecting -> ConnectionRingView.State.Disconnecting
        }
        binding.connectionRing.setState(ringState)

        val accent = ContextCompat.getColor(
            this,
            when (status) {
                AppStatus.Running -> R.color.flow_connected
                AppStatus.Reconnecting -> R.color.flow_reconnecting
                else -> R.color.flow_primary
            },
        )
        val action = when (status) {
            AppStatus.Halted -> R.string.vpn_connect
            AppStatus.Running -> R.string.vpn_disconnect
            AppStatus.Disconnecting -> R.string.vpn_disconnecting
            else -> R.string.action_cancel
        }
        binding.statusAction.setText(action)
        binding.statusButton.contentDescription = getString(action)
        binding.statusAction.setTextColor(accent)
        binding.statusIcon.imageTintList = ColorStateList.valueOf(accent)
        binding.statusButton.alpha = if (status == AppStatus.Disconnecting) 0.6f else 1f

        val title = when (status) {
            AppStatus.Halted -> R.string.vpn_disconnected
            AppStatus.Connecting -> R.string.vpn_connecting
            AppStatus.Running -> R.string.vpn_connected
            AppStatus.Reconnecting -> R.string.vpn_reconnecting
            AppStatus.Disconnecting -> R.string.vpn_disconnecting
        }
        binding.statusTitle.setText(title)
        binding.statusTitle.setTextColor(
            if (status == AppStatus.Running) accent
            else ContextCompat.getColor(this, R.color.flow_text),
        )
        val modeName = getString(
            when (selectedTransport()) {
                TransportMode.Auto -> R.string.mode_auto
                TransportMode.ByeDpi -> R.string.mode_byedpi
                TransportMode.Warp -> R.string.mode_warp
            },
        )
        binding.statusSubtitle.text = when (status) {
            AppStatus.Halted -> getString(R.string.status_sub_halted)
            AppStatus.Connecting -> getString(R.string.status_sub_connecting, modeName)
            AppStatus.Running -> getString(R.string.status_sub_running, modeName)
            AppStatus.Reconnecting -> getString(R.string.status_sub_reconnecting)
            AppStatus.Disconnecting -> getString(R.string.status_sub_disconnecting)
        }
    }

    private fun selectedTransport(): TransportMode = currentTransport

    private fun updateDecision() {
        binding.transportLayout.helperText = getString(TransportOption.descriptionRes(currentTransport))
    }

    private fun saveSplitTunnelRules() {
        binding.domainRulesLayout.error = null
        binding.networkRulesLayout.error = null
        runCatching {
            splitTunnel.validateAndSave(
                binding.domainRulesInput.text?.toString().orEmpty(),
                binding.networkRulesInput.text?.toString().orEmpty(),
            )
        }.onSuccess { rules ->
            binding.domainRulesInput.setText(rules.domainsText())
            binding.networkRulesInput.setText(rules.networksText())
            binding.routingRulesStatus.text = getString(
                R.string.split_rules_saved,
                rules.domains.size,
                rules.networks.size,
            )
        }.onFailure { error ->
            if (error.message?.contains("домен", ignoreCase = true) == true) {
                binding.domainRulesLayout.error = error.message
            } else {
                binding.networkRulesLayout.error = error.message
            }
            binding.routingRulesStatus.text = error.message
        }
    }

    private data class InstalledAppChoice(
        val label: String,
        val packageName: String,
    )

    private fun updateExcludedAppsStatus() {
        val count = appBypass.load().size
        binding.excludedAppsStatus.text = count.toString()
        binding.excludedAppsStatus.visibility = if (count > 0) View.VISIBLE else View.GONE
        binding.excludedAppsStatus.contentDescription =
            getString(R.string.excluded_apps_status, count)
    }

    private fun showAppBypassDialog() {
        val (status, _) = appStatus
        if (status != AppStatus.Halted) {
            Toast.makeText(this, R.string.settings_unavailable, Toast.LENGTH_SHORT).show()
            return
        }

        binding.selectExcludedAppsButton.isEnabled = false
        lifecycleScope.launch {
            val applications = withContext(Dispatchers.Default) { installedAppChoices() }
            binding.selectExcludedAppsButton.isEnabled = appStatus.first == AppStatus.Halted
            if (applications.isEmpty()) {
                Toast.makeText(
                    this@MainActivity,
                    R.string.excluded_apps_empty,
                    Toast.LENGTH_SHORT,
                ).show()
                return@launch
            }

            val selected = appBypass.load().toMutableSet()
            val labels = applications.map { "${it.label}\n${it.packageName}" }.toTypedArray()
            val checked = applications.map { it.packageName in selected }.toBooleanArray()
            MaterialAlertDialogBuilder(this@MainActivity)
                .setTitle(R.string.excluded_apps_dialog_title)
                .setMultiChoiceItems(labels, checked) { _, index, isChecked ->
                    val packageName = applications[index].packageName
                    if (isChecked) selected += packageName else selected -= packageName
                }
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    appBypass.save(selected)
                    updateExcludedAppsStatus()
                }
                .show()
        }
    }

    @Suppress("DEPRECATION")
    private fun installedAppChoices(): List<InstalledAppChoice> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager
        .queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
        .asSequence()
        .map { it.activityInfo.applicationInfo }
        .filter { application -> application.packageName != packageName }
        .map { application ->
            InstalledAppChoice(
                label = application.loadLabel(packageManager).toString()
                    .ifBlank { application.packageName },
                packageName = application.packageName,
            )
        }
        .distinctBy { it.packageName }
        .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
        .toList()
    }

    private fun openAdvancedSettings() {
        val (status, _) = appStatus
        if (status == AppStatus.Halted) {
            startActivity(Intent(this, SettingsActivity::class.java))
        } else {
            Toast.makeText(this, R.string.settings_unavailable, Toast.LENGTH_SHORT).show()
        }
    }

    private fun launchLogExport() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE, "flowcloud.log")
        }
        logsRegister.launch(intent)
    }

    private fun checkForUpdates(manual: Boolean, force: Boolean) {
        if (updateWorkRunning || (!force && !appUpdates.shouldCheckAutomatically())) return
        updateWorkRunning = true
        setUpdateBusy(R.string.checking_updates)
        lifecycleScope.launch {
            try {
                when (val result = appUpdates.check()) {
                    is UpdateCheckResult.Available ->
                        if (manual || !appUpdates.isDismissed(result.release.version)) {
                            showUpdateDialog(result.release)
                        }
                    UpdateCheckResult.UpToDate -> if (manual) {
                        Toast.makeText(
                            this@MainActivity,
                            R.string.app_is_up_to_date,
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                    UpdateCheckResult.NotPublished -> if (manual) {
                        Toast.makeText(
                            this@MainActivity,
                            R.string.updates_not_published,
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                }
            } catch (error: Exception) {
                Log.w(TAG, "Update check failed", error)
                if (manual) {
                    Toast.makeText(
                        this@MainActivity,
                        R.string.update_check_failed,
                        Toast.LENGTH_SHORT,
                    ).show()
                }
            } finally {
                updateWorkRunning = false
                clearUpdateBusy()
            }
        }
    }

    private fun showUpdateDialog(release: AppRelease) {
        val message = buildString {
            append(getString(R.string.update_available_message))
            if (release.notes.isNotBlank()) {
                append("\n\n")
                append(release.notes)
            }
        }
        if (updateDialog?.isShowing == true) return
        updateDialog = MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.update_available_title, release.version))
            .setMessage(message)
            .setNegativeButton(android.R.string.cancel) { _, _ -> appUpdates.dismiss(release.version) }
            .setPositiveButton(R.string.download_update) { _, _ -> downloadUpdate(release) }
            .setOnDismissListener { updateDialog = null }
            .show()
    }

    private fun downloadUpdate(release: AppRelease) {
        if (updateWorkRunning) return
        updateWorkRunning = true
        setUpdateBusy(R.string.downloading_update)
        lifecycleScope.launch {
            try {
                requestUpdateInstallation(appUpdates.download(release))
            } catch (error: UpdateVerificationException) {
                Log.e(TAG, "Downloaded update verification failed", error)
                Toast.makeText(
                    this@MainActivity,
                    R.string.update_verification_failed,
                    Toast.LENGTH_LONG,
                ).show()
            } catch (error: Exception) {
                Log.e(TAG, "Update download failed", error)
                Toast.makeText(
                    this@MainActivity,
                    R.string.update_download_failed,
                    Toast.LENGTH_LONG,
                ).show()
            } finally {
                updateWorkRunning = false
                clearUpdateBusy()
            }
        }
    }

    private fun requestUpdateInstallation(update: File) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !packageManager.canRequestPackageInstalls()
        ) {
            pendingUpdateFile = update
            Toast.makeText(this, R.string.install_permission_required, Toast.LENGTH_LONG).show()
            updateInstallPermissionRegister.launch(
                Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:$packageName"),
                ),
            )
        } else {
            openPackageInstaller(update)
        }
    }

    private fun openPackageInstaller(update: File) {
        if (!update.isFile) {
            Toast.makeText(this, R.string.update_download_failed, Toast.LENGTH_LONG).show()
            return
        }
        val uri = FileProvider.getUriForFile(
            this,
            "$packageName.fileprovider",
            update,
        )
        val install = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        if (install.resolveActivity(packageManager) == null) {
            Toast.makeText(this, R.string.installer_unavailable, Toast.LENGTH_LONG).show()
            return
        }
        startActivity(install)
    }

    private fun setUpdateBusy(status: Int) {
        binding.updateStatus.setText(status)
        binding.updateProgress.visibility = View.VISIBLE
        binding.checkUpdatesButton.isEnabled = false
        binding.automaticUpdatesSwitch.isEnabled = false
    }

    private fun clearUpdateBusy() {
        binding.updateStatus.text = getString(
            R.string.installed_version,
            BuildConfig.VERSION_NAME.removeSuffix("-debug"),
        )
        binding.updateProgress.visibility = View.GONE
        binding.checkUpdatesButton.isEnabled = true
        binding.automaticUpdatesSwitch.isEnabled = true
    }

}
