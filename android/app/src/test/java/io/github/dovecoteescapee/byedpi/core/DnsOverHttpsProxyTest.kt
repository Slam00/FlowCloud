package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsOverHttpsProxyTest {
    @Test
    fun `AAAA query receives empty successful response when IPv6 is disabled`() {
        val query = dnsQuery(type = 28)
        val response = DnsOverHttpsProxy.emptyAaaaResponse(query)

        requireNotNull(response)
        assertEquals(query[0], response[0])
        assertEquals(query[1], response[1])
        assertEquals(0x81, response[2].toInt() and 0xff)
        assertEquals(0x80, response[3].toInt() and 0xff)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0, 0, 0), response.copyOfRange(6, 12))
        assertArrayEquals(query.copyOfRange(12, query.size), response.copyOfRange(12, response.size))
    }

    @Test
    fun `A query is left for the upstream resolver`() {
        assertNull(DnsOverHttpsProxy.emptyAaaaResponse(dnsQuery(type = 1)))
    }

    private fun dnsQuery(type: Int): ByteArray = byteArrayOf(
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 'w'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte(),
        0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
        'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
        0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
        0x00, type.toByte(), 0x00, 0x01,
    )

}
