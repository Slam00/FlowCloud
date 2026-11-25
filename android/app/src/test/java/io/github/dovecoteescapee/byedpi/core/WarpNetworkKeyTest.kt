package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertEquals
import org.junit.Test

class WarpNetworkKeyTest {
    @Test
    fun includesOperatorCodeOnlyWhenValid() {
        assertEquals("cell:25001", WarpNetworkKey.format("cell", "25001"))
        assertEquals("cell:310260", WarpNetworkKey.format("cell", "310260"))
        assertEquals("cell", WarpNetworkKey.format("cell", ""))
        assertEquals("cell", WarpNetworkKey.format("cell", null))
        assertEquals("cell", WarpNetworkKey.format("cell", "123"))
        assertEquals("cell:25099", WarpNetworkKey.format("cell", "250-99"))
        assertEquals("wifi", WarpNetworkKey.format("wifi", null))
    }
}
