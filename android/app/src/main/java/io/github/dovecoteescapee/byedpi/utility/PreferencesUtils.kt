package io.github.dovecoteescapee.byedpi.utility

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.PreferenceManager
import io.github.dovecoteescapee.byedpi.data.Mode
import io.github.dovecoteescapee.byedpi.data.TransportMode

val PreferenceFragmentCompat.sharedPreferences
    get() = preferenceScreen.sharedPreferences

fun Context.getPreferences(): SharedPreferences =
    PreferenceManager.getDefaultSharedPreferences(this)

fun SharedPreferences.getStringNotNull(key: String, defValue: String): String =
    getString(key, defValue) ?: defValue

fun SharedPreferences.mode(): Mode =
    Mode.fromString(getStringNotNull("byedpi_mode", "vpn"))

private const val TRANSPORT_MODE_KEY = "transport_mode"

/** The connection mode last chosen on the main screen; used by every start path. */
fun SharedPreferences.transportMode(): TransportMode =
    TransportMode.fromName(getString(TRANSPORT_MODE_KEY, null))

fun SharedPreferences.saveTransportMode(mode: TransportMode) {
    edit().putString(TRANSPORT_MODE_KEY, mode.name.lowercase()).apply()
}

fun <T : Preference> PreferenceFragmentCompat.findPreferenceNotNull(key: CharSequence): T =
    findPreference(key) ?: throw IllegalStateException("Preference $key not found")
