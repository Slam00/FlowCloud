package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager

/**
 * Identifies the physical network WARP endpoints were measured on, so the route
 * engine keeps separate known-good endpoints for mobile operators and Wi-Fi.
 * Uses only data that needs no runtime permission: the transport type and, on
 * mobile data, the operator's MCC+MNC.
 */
object WarpNetworkKey {
    fun of(context: Context, network: Network?): String {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = network?.let { runCatching { connectivity.getNetworkCapabilities(it) }.getOrNull() }
        return when {
            capabilities == null -> "unknown"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                format("cell", cellularOperator(context))
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
    }

    fun format(transport: String, operator: String?): String {
        val code = operator?.filter(Char::isDigit).orEmpty()
        return if (code.length in 5..6) "$transport:$code" else transport
    }

    private fun cellularOperator(context: Context): String? = runCatching {
        val telephony = context.getSystemService(TelephonyManager::class.java)
        val subscription = SubscriptionManager.getDefaultDataSubscriptionId()
        val scoped = if (subscription != SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
            telephony.createForSubscriptionId(subscription)
        } else {
            telephony
        }
        scoped.networkOperator
    }.getOrNull()
}
