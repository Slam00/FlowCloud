package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainRulesTest {
    @Test
    fun normalizeAcceptsDomainAndUrl() {
        assertEquals("example.com", DomainRules.normalize("Example.COM"))
        assertEquals("sub.example.com", DomainRules.normalize("https://Sub.Example.com/path?q=1"))
        assertNull(DomainRules.normalize("  "))
    }

    @Test
    fun matcherIncludesSubdomainsWithoutMatchingLookalikes() {
        val rules = DomainRules.parse(sequenceOf("example.com", "# comment", ".geo.test"))

        assertTrue(DomainRules.matches(rules, "example.com"))
        assertTrue(DomainRules.matches(rules, "video.example.com"))
        assertTrue(DomainRules.matches(rules, "cdn.geo.test"))
        assertFalse(DomainRules.matches(rules, "notexample.com"))
    }
}
