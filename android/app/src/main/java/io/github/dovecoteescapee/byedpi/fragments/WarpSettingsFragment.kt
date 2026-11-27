package io.github.dovecoteescapee.byedpi.fragments

import android.os.Bundle
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.data.TransportMode
import io.github.dovecoteescapee.byedpi.utility.*

/** Settings → WARP: options of the WARP tunnel, used in the Авто and WARP modes. */
class WarpSettingsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.warp_settings, rootKey)
    }

    override fun onResume() {
        super.onResume()
        setScreenTitle(R.string.warp_category)
        // The mode is chosen on the main screen; settings open only while disconnected.
        val warpUsed = sharedPreferences?.transportMode() != TransportMode.ByeDpi
        findPreferenceNotNull<Preference>("warp_mode_note").isVisible = !warpUsed
        findPreferenceNotNull<Preference>("warp_avoid_colos").isEnabled = warpUsed
    }
}
