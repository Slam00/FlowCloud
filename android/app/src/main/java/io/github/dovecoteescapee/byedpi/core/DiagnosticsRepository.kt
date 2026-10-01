package io.github.dovecoteescapee.byedpi.core

import android.content.Context
import android.os.Build
import io.github.dovecoteescapee.byedpi.BuildConfig
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DiagnosticsRepository {
    private const val FILE_NAME = "flowcloud-diagnostics.log"
    private const val PREVIOUS_FILE_NAME = "flowcloud-diagnostics.previous.log"
    private const val MAX_FILE_BYTES = 512 * 1024L
    private val lock = Any()

    fun beginSession(context: Context, transport: String) = synchronized(lock) {
        val current = file(context)
        if (current.exists()) {
            runCatching { current.copyTo(File(context.filesDir, PREVIOUS_FILE_NAME), overwrite = true) }
        }
        current.writeText(
            buildString {
                appendLine("${timestamp()} FlowCloud ${BuildConfig.VERSION_NAME}")
                appendLine("${timestamp()} Device: ${Build.MANUFACTURER} ${Build.MODEL}; Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                appendLine("${timestamp()} Requested transport: $transport")
            },
        )
    }

    fun append(context: Context, source: String, message: String) = synchronized(lock) {
        val target = file(context)
        trimIfNeeded(target)
        target.appendText(
            message.lineSequence()
                .filter { it.isNotBlank() }
                .joinToString(separator = "\n", postfix = "\n") { line ->
                    if (line.matches(Regex("^\\d{4}-\\d{2}-\\d{2} .*"))) line
                    else "${timestamp()} $source: $line"
                },
        )
    }

    fun append(context: Context, source: String, error: Throwable) {
        val trace = StringWriter().also { writer ->
            error.printStackTrace(PrintWriter(writer))
        }.toString()
        append(context, source, trace)
    }

    fun read(context: Context): String = synchronized(lock) {
        buildString {
            val previous = File(context.filesDir, PREVIOUS_FILE_NAME)
            if (previous.exists()) {
                appendLine("--- Previous FlowCloud session ---")
                append(previous.readText())
                appendLine()
            }
            val current = file(context)
            appendLine("--- Current FlowCloud session ---")
            if (current.exists()) append(current.readText()) else appendLine("No internal diagnostics were recorded.")
        }
    }

    private fun file(context: Context) = File(context.filesDir, FILE_NAME)

    private fun trimIfNeeded(target: File) {
        if (!target.exists() || target.length() <= MAX_FILE_BYTES) return
        val tail = target.readText().takeLast((MAX_FILE_BYTES / 2).toInt())
        target.writeText("${timestamp()} Diagnostics truncated to the newest entries.\n$tail")
    }

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
}
