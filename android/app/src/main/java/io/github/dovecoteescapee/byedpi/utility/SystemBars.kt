package io.github.dovecoteescapee.byedpi.utility

import android.app.Activity
import android.content.res.Configuration
import androidx.core.view.WindowCompat

/** Dark icons on light bars and light icons on dark bars, following the app's own night mode. */
fun Activity.applySystemBarAppearance() {
    val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
        Configuration.UI_MODE_NIGHT_YES
    WindowCompat.getInsetsController(window, window.decorView).apply {
        isAppearanceLightStatusBars = !night
        isAppearanceLightNavigationBars = !night
    }
}
