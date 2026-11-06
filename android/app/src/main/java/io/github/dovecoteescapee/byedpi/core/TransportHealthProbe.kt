package io.github.dovecoteescapee.byedpi.core

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.random.Random

/**
 * End-to-end checks of the running transport, used by the VPN watchdog to detect a
 * chain that is up but no longer passes traffic (the "hangs until reconnect" case).
 * All calls block; run them off the main thread.
 */
object TransportHealthProbe {
    data class HttpTarget(val host: String, val path: String)

    /** Any one of these answering proves the path works; several avoid false alarms when one is blocked. */
    val defaultHttpTargets = listOf(
        HttpTarget("ya.ru", "/"),
        HttpTarget("connectivitycheck.gstatic.com", "/generate_204"),
        HttpTarget("www.cloudflare.com", "/cdn-cgi/trace"),
    )

    /** Sends an A query for [name] to the local DNS relay ("127.0.0.1:port"). */
    fun dnsRelayAnswers(relayAddress: String, name: String = "ya.ru", timeoutMs: Int = 4_000): Boolean {
        val host = relayAddress.substringBeforeLast(':')
        val port = relayAddress.substringAfterLast(':').toIntOrNull() ?: return false
        val query = buildDnsQuery(name)
        return runCatching {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                socket.send(DatagramPacket(query, query.size, InetSocketAddress(host, port)))
                val buffer = ByteArray(1_500)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                isDnsResponseTo(query, buffer, response.length)
            }
        }.getOrDefault(false)
    }

    /** True when an HTTP request through the SOCKS5 proxy on 127.0.0.1:[socksPort] gets any HTTP reply. */
    fun socksPassesHttp(socksPort: Int, targets: List<HttpTarget> = defaultHttpTargets): Boolean =
        targets.any { socksHttpRequest(socksPort, it) }

    private fun socksHttpRequest(socksPort: Int, target: HttpTarget, timeoutMs: Int = 6_000): Boolean =
        runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2_000)
                socket.soTimeout = timeoutMs
                val output = socket.getOutputStream()
                val input = DataInputStream(socket.getInputStream())
                output.write(byteArrayOf(5, 1, 0))
                val greeting = ByteArray(2).also { input.readFully(it) }
                if (greeting[0] != 5.toByte() || greeting[1] != 0.toByte()) return@use false
                output.write(socksConnectRequest(target.host, 80))
                val reply = ByteArray(4).also { input.readFully(it) }
                if (reply[1] != 0.toByte()) return@use false
                skipBoundAddress(input, reply[3].toInt())
                output.write(
                    ("GET ${target.path} HTTP/1.1\r\nHost: ${target.host}\r\n" +
                        "User-Agent: FlowCloud-health\r\nConnection: close\r\n\r\n").toByteArray(),
                )
                output.flush()
                val head = ByteArray(5).also { input.readFully(it) }
                String(head, Charsets.US_ASCII) == "HTTP/"
            }
        }.getOrDefault(false)

    internal fun socksConnectRequest(host: String, port: Int): ByteArray {
        val name = host.toByteArray(Charsets.US_ASCII)
        require(name.size in 1..255)
        return byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name +
            byteArrayOf((port shr 8).toByte(), port.toByte())
    }

    private fun skipBoundAddress(input: DataInputStream, addressType: Int) {
        val length = when (addressType) {
            1 -> 4
            4 -> 16
            3 -> input.readUnsignedByte()
            else -> throw IllegalStateException("Bad SOCKS address type $addressType")
        }
        input.skipFully(length + 2L)
    }

    // Not InputStream.skipNBytes: that member only exists on API 33+.
    private fun DataInputStream.skipFully(count: Long) {
        var remaining = count
        while (remaining > 0) {
            val skipped = skip(remaining)
            if (skipped <= 0) {
                read().takeIf { it >= 0 } ?: throw java.io.EOFException()
                remaining--
            } else {
                remaining -= skipped
            }
        }
    }

    internal fun buildDnsQuery(name: String, id: Int = Random.nextInt(0, 0x10000)): ByteArray {
        val labels = name.trimEnd('.').split('.').flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        }
        return byteArrayOf(
            (id shr 8).toByte(), id.toByte(),
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ) + labels.toByteArray() + byteArrayOf(0x00, 0x00, 0x01, 0x00, 0x01)
    }

    internal fun isDnsResponseTo(query: ByteArray, response: ByteArray, length: Int): Boolean =
        length >= 12 &&
            response[0] == query[0] &&
            response[1] == query[1] &&
            (response[2].toInt() and 0x80) != 0
}
