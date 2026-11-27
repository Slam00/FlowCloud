package io.github.dovecoteescapee.byedpi.fragments

import android.os.Bundle
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreference
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.data.TransportMode
import io.github.dovecoteescapee.byedpi.utility.*

/** Settings → ByeDPI: which editor defines the desync strategy, and both editors. */
class ByeDpiSettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.byedpi_settings, rootKey)

        val switchCommandLineSettings = findPreferenceNotNull<SwitchPreference>(
            "byedpi_enable_cmd_settings"
        )
        val uiSettings = findPreferenceNotNull<Preference>("byedpi_ui_settings")
        val cmdSettings = findPreferenceNotNull<Preference>("byedpi_cmd_settings")

        val setByeDpiSettingsMode = { enable: Boolean ->
            uiSettings.isEnabled = !enable
            cmdSettings.isEnabled = enable
        }

        setByeDpiSettingsMode(switchCommandLineSettings.isChecked)

        switchCommandLineSettings.setOnPreferenceChangeListener { _, newValue ->
            setByeDpiSettingsMode(newValue as Boolean)
            true
        }
    }

    override fun onResume() {
        super.onResume()
        setScreenTitle(R.string.byedpi_category)
        // In WARP mode ByeDPI still carries the WARP registration requests, so its
        // options stay editable; the note says what they affect in each mode.
        findPreferenceNotNull<Preference>("byedpi_mode_note").setSummary(
            when (sharedPreferences?.transportMode()) {
                TransportMode.Warp -> R.string.byedpi_note_warp
                TransportMode.ByeDpi -> R.string.byedpi_note_byedpi
                else -> R.string.byedpi_note_auto
            }
        )
    }
}
