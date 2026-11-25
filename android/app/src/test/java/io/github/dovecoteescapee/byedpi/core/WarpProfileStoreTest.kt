package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WarpProfileStoreTest {
    @Test
    fun envelopeRoundTrips() {
        val text = ProfileEnvelope.format("aXY=", "Y2lwaGVy")
        assertEquals("v1:aXY=:Y2lwaGVy", text)
        assertEquals("aXY=" to "Y2lwaGVy", ProfileEnvelope.parse(text))
    }

    @Test
    fun envelopeRejectsOtherShapes() {
        assertNull(ProfileEnvelope.parse(""))
        assertNull(ProfileEnvelope.parse("v2:aXY=:Y2lwaGVy"))
        assertNull(ProfileEnvelope.parse("v1::Y2lwaGVy"))
        assertNull(ProfileEnvelope.parse("v1:aXY=:"))
        assertNull(ProfileEnvelope.parse("v1:a:b:c"))
        // A legacy plain-text value is never mistaken for an envelope.
        assertNull(ProfileEnvelope.parse("{\"private_key\":\"abc\"}"))
    }
}
