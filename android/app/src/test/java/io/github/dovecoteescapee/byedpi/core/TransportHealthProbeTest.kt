package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportHealthProbeTest {
    @Test
    fun buildsStandardAQuery() {
        val query = TransportHealthProbe.buildDnsQuery("ya.ru", id = 0x1234)
        val expected = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
            2, 'y'.code.toByte(), 'a'.code.toByte(),
            2, 'r'.code.toByte(), 'u'.code.toByte(),
            0, 0x00, 0x01, 0x00, 0x01,
        )
        assertArrayEquals(expected, query)
    }

    @Test
    fun acceptsOnlyMatchingResponses() {
        val query = TransportHealthProbe.buildDnsQuery("ya.ru", id = 0x1234)
        val response = query.copyOf().apply { this[2] = (this[2].toInt() or 0x80).toByte() }
        assertTrue(TransportHealthProbe.isDnsResponseTo(query, response, response.size))
        assertFalse(TransportHealthProbe.isDnsResponseTo(query, query, query.size)) // not a response
        val otherId = response.copyOf().apply { this[1] = 0x35 }
        assertFalse(TransportHealthProbe.isDnsResponseTo(query, otherId, otherId.size))
        assertFalse(TransportHealthProbe.isDnsResponseTo(query, response, 8))
    }

    @Test
    fun encodesSocksDomainConnect() {
        val request = TransportHealthProbe.socksConnectRequest("ya.ru", 80)
        val expected = byteArrayOf(5, 1, 0, 3, 5) + "ya.ru".toByteArray() + byteArrayOf(0, 80)
        assertArrayEquals(expected, request)
    }
}
