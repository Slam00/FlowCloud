package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DnsOverHttpsProxy(context: Context) {
    private data class Provider(
        val url: String,
        val host: String,
        val addresses: List<String>,
    )

    companion object {
        private const val TAG = "DnsOverHttpsProxy"
        private val DNS_MESSAGE = "application/dns-message".toMediaType()
        private val providers = listOf(
            Provider(
                url = "https://dns.google/dns-query",
                host = "dns.google",
                addresses = listOf(
                    "8.8.8.8", "8.8.4.4",
                    "2001:4860:4860::8888", "2001:4860:4860::8844",
                ),
            ),
            Provider(
                url = "https://cloudflare-dns.com/dns-query",
                host = "cloudflare-dns.com",
                addresses = listOf(
                    "1.1.1.1", "1.0.0.1",
                    "2606:4700:4700::1111", "2606:4700:4700::1001",
                ),
            ),
            Provider(
                url = "https://dns.quad9.net/dns-query",
                host = "dns.quad9.net",
                addresses = listOf(
                    "9.9.9.9", "149.112.112.112",
                    "2620:fe::fe", "2620:fe::9",
                ),
            ),
        )

        internal fun emptyAaaaResponse(query: ByteArray): ByteArray? {
            if (query.size < 17 || readUnsignedShort(query, 4) != 1) return null

            var offset = 12
            while (offset < query.size) {
                val labelLength = query[offset].toInt() and 0xff
                offset++
                if (labelLength == 0) break
                if (labelLength and 0xc0 != 0 || labelLength > 63) return null
                if (offset + labelLength > query.size) return null
                offset += labelLength
            }
            if (offset + 4 > query.size) return null

            val queryType = readUnsignedShort(query, offset)
            if (queryType != 28) return null
            val questionEnd = offset + 4
            return query.copyOf(questionEnd).apply {
                this[2] = (this[2].toInt() or 0x80).toByte()
                this[3] = ((this[3].toInt() and 0x70) or 0x80).toByte()
                for (index in 6..11) this[index] = 0
            }
        }

        private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xff) shl 8) or
                (bytes[offset + 1].toInt() and 0xff)
    }

    private val connectivityManager = context.applicationContext
        .getSystemService(ConnectivityManager::class.java)

    @Volatile
    private var socket: DatagramSocket? = null
    @Volatile
    private var ipv6Enabled = false
    private var receiver: Thread? = null
    private var queryExecutor: ExecutorService? = null
    private var providerExecutor: ExecutorService? = null

    private val client = OkHttpClient.Builder()
        .dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                val provider = providers.firstOrNull {
                    it.host.equals(hostname, ignoreCase = true)
                }
                return provider?.addresses?.mapNotNull { parseAddress(hostname, it) }
                    ?.takeIf { it.isNotEmpty() }
                    ?: Dns.SYSTEM.lookup(hostname)
            }
        })
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .callTimeout(7, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    @Synchronized
    fun start(ipv6Enabled: Boolean): String {
        check(socket == null) { "DNS proxy is already running" }
        this.ipv6Enabled = ipv6Enabled
        val datagramSocket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        }
        val queryPool = Executors.newFixedThreadPool(4) { task ->
            Thread(task, "FlowCloud-DNS-query").apply { isDaemon = true }
        }
        val providerPool = Executors.newFixedThreadPool(16) { task ->
            Thread(task, "FlowCloud-DNS-provider").apply { isDaemon = true }
        }
        socket = datagramSocket
        queryExecutor = queryPool
        providerExecutor = providerPool
        receiver = Thread({ receiveLoop(datagramSocket, queryPool) }, "FlowCloud-DNS-receiver")
            .apply {
                isDaemon = true
                start()
            }
        val address = "127.0.0.1:${datagramSocket.localPort}"
        Log.i(TAG, "DNS-over-HTTPS relay started at $address")
        return address
    }

    @Synchronized
    fun stop() {
        val activeSocket = socket ?: return
        socket = null
        activeSocket.close()
        receiver?.join(1_000)
        receiver = null
        queryExecutor?.shutdownNow()
        providerExecutor?.shutdownNow()
        queryExecutor = null
        providerExecutor = null
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        Log.i(TAG, "DNS-over-HTTPS relay stopped")
    }

    private fun receiveLoop(activeSocket: DatagramSocket, executor: ExecutorService) {
        while (!activeSocket.isClosed) {
            val buffer = ByteArray(65_535)
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                activeSocket.receive(packet)
            } catch (_: SocketException) {
                return
            } catch (error: Exception) {
                Log.w(TAG, "Failed to receive DNS query", error)
                continue
            }
            val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
            val clientAddress = packet.address
            val clientPort = packet.port
            executor.execute {
                val response = resolve(query) ?: return@execute
                try {
                    activeSocket.send(
                        DatagramPacket(response, response.size, clientAddress, clientPort),
                    )
                } catch (_: SocketException) {
                    // The VPN is stopping.
                } catch (error: Exception) {
                    Log.w(TAG, "Failed to return DNS response", error)
                }
            }
        }
    }

    private fun resolve(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        if (!ipv6Enabled) {
            emptyAaaaResponse(query)?.let { return it }
        }
        val executor = providerExecutor ?: return null
        val completion = ExecutorCompletionService<ByteArray?>(executor)
        val futures = providers.map { provider ->
            completion.submit { request(provider, query) }
        }.toMutableList()
        futures += completion.submit {
            try {
                Thread.sleep(600)
            } catch (_: InterruptedException) {
                return@submit null
            }
            requestViaUnderlyingNetwork(query)
        }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
        try {
            repeat(futures.size) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) return null
                val future = completion.poll(remaining, TimeUnit.NANOSECONDS) ?: return null
                val response = runCatching { future.get() }.getOrNull()
                if (response != null) return response
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return null
        } finally {
            futures.forEach { it.cancel(true) }
        }
        return null
    }

    private fun request(provider: Provider, query: ByteArray): ByteArray? {
        val request = Request.Builder()
            .url(provider.url)
            .header("Accept", DNS_MESSAGE.toString())
            .post(query.toRequestBody(DNS_MESSAGE))
            .build()
        return runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@use null
                val payload = response.body?.bytes() ?: return@use null
                if (!isValidResponse(query, payload)) {
                    return@use null
                }
                payload
            }
        }.getOrNull()
    }

    private fun requestViaUnderlyingNetwork(query: ByteArray): ByteArray? {
        val networks = runCatching { connectivityManager.allNetworks.toList() }
            .getOrDefault(emptyList())
            .filter { network ->
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                    ?: return@filter false
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
            .sortedByDescending { network ->
                val capabilities = connectivityManager.getNetworkCapabilities(network)
                when {
                    capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 2
                    capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true -> 1
                    else -> 0
                }
            }

        for (network in networks) {
            val dnsServers = connectivityManager.getLinkProperties(network)?.dnsServers.orEmpty()
            for (dnsServer in dnsServers) {
                val response = queryNetworkDns(network, dnsServer, query)
                if (response != null) return response
            }
        }
        return null
    }

    private fun queryNetworkDns(
        network: Network,
        dnsServer: InetAddress,
        query: ByteArray,
    ): ByteArray? = runCatching {
        DatagramSocket().use { datagramSocket ->
            network.bindSocket(datagramSocket)
            datagramSocket.soTimeout = 1_500
            datagramSocket.connect(InetSocketAddress(dnsServer, 53))
            datagramSocket.send(DatagramPacket(query, query.size))
            val buffer = ByteArray(65_535)
            val response = DatagramPacket(buffer, buffer.size)
            datagramSocket.receive(response)
            buffer.copyOfRange(response.offset, response.offset + response.length)
                .takeIf { isValidResponse(query, it) }
        }
    }.getOrNull()

    private fun isValidResponse(query: ByteArray, response: ByteArray): Boolean =
        response.size >= 12 &&
            response[0] == query[0] &&
            response[1] == query[1] &&
            response[2].toInt() and 0x80 != 0

    private fun parseAddress(host: String, value: String): InetAddress? {
        if (value.contains(':')) {
            return runCatching {
                InetAddress.getByAddress(host, InetAddress.getByName(value).address)
            }.getOrNull()
        }
        val parts = value.split('.')
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for (index in parts.indices) {
            val octet = parts[index].toIntOrNull()?.takeIf { it in 0..255 } ?: return null
            bytes[index] = octet.toByte()
        }
        return InetAddress.getByAddress(host, bytes)
    }

}
