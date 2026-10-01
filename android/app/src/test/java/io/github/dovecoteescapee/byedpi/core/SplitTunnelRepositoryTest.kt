package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SplitTunnelRepositoryTest {
    @Test
    fun normalizesDomainRules() {
        assertEquals("api.example.com", SplitTunnelRepository.normalizeDomain("https://API.Example.com/path"))
        assertEquals("example.com", SplitTunnelRepository.normalizeDomain("*.example.com"))
        assertNull(SplitTunnelRepository.normalizeDomain("1.1.1.1"))
    }

    @Test
    fun normalizesNumericRoutes() {
        assertEquals("149.154.160.0/20", SplitTunnelRepository.normalizeNetwork("149.154.160.0/20"))
        assertEquals("1.1.1.1/32", SplitTunnelRepository.normalizeNetwork("1.1.1.1"))
        assertEquals("2001:b28:f23f::/48", SplitTunnelRepository.normalizeNetwork("2001:b28:f23f::/48"))
        assertNull(SplitTunnelRepository.normalizeNetwork("999.1.1.1"))
    }
}
