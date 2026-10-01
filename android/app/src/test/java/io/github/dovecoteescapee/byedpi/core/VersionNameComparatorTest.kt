package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VersionNameComparatorTest {
    @Test
    fun detectsNewVersionFromGitHubTag() {
        assertTrue(VersionNameComparator.isNewer("v0.2.4", "0.2.3-debug"))
        assertTrue(VersionNameComparator.isNewer("android-v1.0.0", "0.9.9"))
    }

    @Test
    fun rejectsSameOrOlderVersion() {
        assertFalse(VersionNameComparator.isNewer("v0.2.3", "0.2.3-debug"))
        assertFalse(VersionNameComparator.isNewer("v0.2.2", "0.2.3"))
    }
}
