package io.github.dovecoteescapee.byedpi.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ByeDpiAutoStrategiesTest {
    private val base = ByeDpiProxyUIPreferences().toArgs()

    @Test
    fun userStrategyStaysFirstAndFallbacksFollowInOrder() {
        val args = ByeDpiAutoStrategies.augment(base, File("/data/cache"), 600).toList()
        assertEquals(base.toList(), args.take(base.size))
        val tail = args.drop(base.size)
        assertEquals(listOf("-T", "4"), tail.take(2))

        val groupStarts = tail.indices.filter { tail[it] == "-A" }
        assertEquals(ByeDpiAutoStrategies.strategies.size, groupStarts.size)
        val comments = tail.indices.filter { tail[it] == "--comment" }.map { tail[it + 1] }
        assertEquals(ByeDpiAutoStrategies.strategies.map { "flowcloud-${it.name}" }, comments)
    }

    @Test
    fun everyFallbackGroupHasTriggersTtlAndOwnCacheFile() {
        val args = ByeDpiAutoStrategies.augment(base, File("/data/cache"), 600).toList()
        val groups = splitGroups(args.drop(base.size + 2))
        groups.forEachIndexed { index, group ->
            assertTrue(group[1].split(',').all { it in setOf("t", "s", "r") })
            assertEquals("600", group[group.indexOf("-u") + 1])
            assertEquals(
                File("/data/cache", "byedpi-auto-$index.cache").absolutePath,
                group[group.indexOf("-y") + 1],
            )
        }
    }

    @Test
    fun userAutoGroupsAreRespected() {
        val custom = arrayOf("ciadpi", "-d", "1", "-A", "t", "-s", "1")
        assertArrayEquals(custom, ByeDpiAutoStrategies.augment(custom, null))
        val long = arrayOf("ciadpi", "--auto=torst", "-s", "1")
        assertArrayEquals(long, ByeDpiAutoStrategies.augment(long, null))
    }

    @Test
    fun userTimeoutIsKeptAndCacheFileIsOptional() {
        val custom = arrayOf("ciadpi", "-T", "2", "-d", "1")
        val args = ByeDpiAutoStrategies.augment(custom, null).toList()
        assertEquals(1, args.count { it == "-T" })
        assertTrue("-y" !in args)
    }

    @Test
    fun ttlHasAFloor() {
        val args = ByeDpiAutoStrategies.augment(base, null, 1).toList()
        assertTrue(args.indices.filter { args[it] == "-u" }.all { args[it + 1] == "60" })
    }

    @Test
    fun cmdPreferencesAreWrapped() {
        val wrapped = ByeDpiAutoStrategies.forAutoMode(ByeDpiProxyCmdPreferences("-d 1"), null)
        assertEquals(listOf("ciadpi", "-d", "1"), wrapped.args.take(3))
        assertTrue("-A" in wrapped.args)
    }

    private fun splitGroups(args: List<String>): List<List<String>> {
        val groups = mutableListOf<MutableList<String>>()
        for (arg in args) {
            if (arg == "-A") groups += mutableListOf<String>()
            groups.last() += arg
        }
        return groups
    }
}
