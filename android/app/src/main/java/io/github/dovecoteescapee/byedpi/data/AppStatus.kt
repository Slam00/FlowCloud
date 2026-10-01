package io.github.dovecoteescapee.byedpi.data

enum class AppStatus {
    Halted,
    Connecting,
    Reconnecting,
    Disconnecting,
    Running,
}

enum class Mode {
    Proxy,
    VPN;

    companion object {
        fun fromSender(sender: Sender): Mode = when (sender) {
            Sender.Proxy -> Proxy
            Sender.VPN, Sender.WARP -> VPN
        }

        fun fromString(name: String): Mode = when (name) {
            "proxy" -> Proxy
            "vpn" -> VPN
            else -> throw IllegalArgumentException("Invalid mode: $name")
        }
    }
}

enum class TransportMode {
    Auto,
    ByeDpi,
    Warp;

    companion object {
        fun fromName(name: String?): TransportMode = when (name) {
            "byedpi" -> ByeDpi
            "warp" -> Warp
            else -> Auto
        }
    }
}
