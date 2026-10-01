package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import io.github.dovecoteescapee.byedpi.utility.getPreferences

class AppBypassRepository(context: Context) {
    companion object {
        private const val PACKAGES_KEY = "vpn_bypass_packages"
    }

    private val preferences = context.getPreferences()

    fun load(): Set<String> = preferences
        .getStringSet(PACKAGES_KEY, emptySet())
        .orEmpty()
        .filterTo(sortedSetOf()) { it.isNotBlank() }

    fun save(packages: Set<String>) {
        preferences.edit()
            .putStringSet(PACKAGES_KEY, packages.filterTo(mutableSetOf()) { it.isNotBlank() })
            .apply()
    }
}
