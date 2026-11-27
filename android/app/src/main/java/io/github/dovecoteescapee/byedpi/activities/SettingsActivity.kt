package io.github.dovecoteescapee.byedpi.activities

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.fragments.ByeDpiSettingsFragment
import io.github.dovecoteescapee.byedpi.fragments.MainSettingsFragment
import io.github.dovecoteescapee.byedpi.fragments.WarpSettingsFragment
import io.github.dovecoteescapee.byedpi.utility.applySystemBarAppearance
import io.github.dovecoteescapee.byedpi.utility.getPreferences

/** Hosts one settings screen opened from the Settings tab (Сеть, WARP or ByeDPI). */
class SettingsActivity : AppCompatActivity() {
    enum class Screen { Network, Warp, ByeDpi }

    companion object {
        private const val EXTRA_SCREEN = "screen"

        fun intent(context: Context, screen: Screen): Intent =
            Intent(context, SettingsActivity::class.java).putExtra(EXTRA_SCREEN, screen.name)
    }

    private val screen: Screen
        get() = intent.getStringExtra(EXTRA_SCREEN)
            ?.let { name -> Screen.entries.firstOrNull { it.name == name } }
            ?: Screen.Network

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        setSupportActionBar(findViewById(R.id.toolbar))
        applySystemBarAppearance()

        if (savedInstanceState == null) {
            showRootScreen()
        }

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
    }

    private fun rootFragment(): Fragment = when (screen) {
        Screen.Network -> MainSettingsFragment()
        Screen.Warp -> WarpSettingsFragment()
        Screen.ByeDpi -> ByeDpiSettingsFragment()
    }

    private fun showRootScreen() {
        supportFragmentManager
            .beginTransaction()
            .replace(R.id.settings, rootFragment())
            .commit()
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.menu_settings, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        android.R.id.home -> {
            onBackPressedDispatcher.onBackPressed()
            true
        }

        R.id.action_reset_settings -> {
            getPreferences().edit().clear().apply()

            supportFragmentManager.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
            showRootScreen()
            true
        }

        else -> super.onOptionsItemSelected(item)
    }
}
