package io.github.dovecoteescapee.byedpi.core

import io.github.dovecoteescapee.byedpi.core.ByeDpiProxyUIPreferences.DesyncMethod
import io.github.dovecoteescapee.byedpi.core.ByeDpiProxyUIPreferences.HostsMode
import org.junit.Assert.assertEquals
import org.junit.Test

class ByeDpiProxyUIPreferencesTest {
    @Test
    fun defaultsProduceSingleTcpGroup() {
        val args = ByeDpiProxyUIPreferences().toArgs().toList()
        assertEquals(
            listOf(
                "ciadpi", "-i", "127.0.0.1", "-p", "1080", "-c", "512", "-b", "16384",
                "-K", "t,h", "-d", "1", "-r", "1+s",
            ),
            args,
        )
    }

    @Test
    fun fakeWithHostOffsetAndTlsRecord() {
        val args = ByeDpiProxyUIPreferences(
            desyncMethod = DesyncMethod.Fake,
            splitAtHost = true,
            fakeTtl = 5,
            fakeSni = "example.org",
            byedpiFakeOffset = 3,
            tlsRecordSplit = true,
            tlsRecordSplitPosition = 2,
            tlsRecordSplitAtSni = true,
        ).toArgs().toList()
        assertEquals(
            listOf("-K", "t,h", "-f", "1+s", "-t", "5", "-n", "example.org", "-O", "3", "-r", "2+s"),
            args.drop(9),
        )
    }

    @Test
    fun whitelistHostsBypassDesyncAndUdpGetsOwnGroup() {
        val args = ByeDpiProxyUIPreferences(
            desyncHttp = false,
            tlsRecordSplit = false,
            desyncUdp = true,
            udpFakeCount = 2,
            hostsMode = HostsMode.Whitelist,
            hosts = "a.com\n b.com ",
        ).toArgs().toList()
        assertEquals(
            listOf("-H", ":a.com b.com", "-An", "-K", "t", "-d", "1", "-An", "-K", "u", "-a", "2"),
            args.drop(9),
        )
    }

    @Test
    fun blacklistHostsLimitDesyncGroup() {
        val args = ByeDpiProxyUIPreferences(
            desyncMethod = DesyncMethod.OOB,
            tlsRecordSplit = false,
            oobChar = "\\",
            hostsMode = HostsMode.Blacklist,
            hosts = "x.org",
        ).toArgs().toList()
        assertEquals(
            listOf("-K", "t,h", "-H", ":x.org", "-o", "1", "-e", "\\\\"),
            args.drop(9),
        )
    }

    @Test
    fun cmdPreferencesDropExitingOptions() {
        val args = ByeDpiProxyCmdPreferences("ciadpi -h -d 1 --version").args.toList()
        assertEquals(listOf("ciadpi", "-d", "1"), args)
    }
}
