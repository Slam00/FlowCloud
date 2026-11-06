package io.github.dovecoteescapee.byedpi.views

import android.animation.TimeAnimator
import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.graphics.RectF
import android.os.Build
import android.util.AttributeSet
import android.view.View
import androidx.annotation.ColorRes
import androidx.core.content.ContextCompat
import io.github.dovecoteescapee.byedpi.R
import kotlin.math.PI
import kotlin.math.sin

/**
 * Ring around the connection button. Its colour and motion show the connection state:
 * a quiet track when off, a rotating arc while connecting, a solid ring with a slow
 * halo when connected, and a slower amber arc on a dotted track while reconnecting.
 */
class ConnectionRingView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    enum class State { Halted, Connecting, Running, Reconnecting, Disconnecting }

    private val density = resources.displayMetrics.density
    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeWidth = 4 * density
    }
    private val haloPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 14 * density
    }
    private val dots = DashPathEffect(floatArrayOf(2 * density, 9 * density), 0f)
    private val ring = RectF()

    private var state = State.Halted
    private var elapsedMs = 0L
    private val animator = TimeAnimator().apply {
        setTimeListener { _, total, _ ->
            elapsedMs = total
            invalidate()
        }
    }

    fun setState(value: State) {
        if (state == value) return
        state = value
        elapsedMs = 0L
        invalidate()
        updateAnimation()
    }

    private fun color(@ColorRes id: Int) = ContextCompat.getColor(context, id)

    private fun motionEnabled(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || ValueAnimator.areAnimatorsEnabled()

    private fun updateAnimation() {
        val shouldRun = state != State.Halted && motionEnabled() &&
            isAttachedToWindow && isShown && windowVisibility == VISIBLE
        if (shouldRun) {
            if (!animator.isStarted) animator.start()
        } else {
            animator.cancel()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        updateAnimation()
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        super.onDetachedFromWindow()
    }

    override fun onVisibilityChanged(changedView: View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        // Visibility callbacks can arrive while the View constructor is running.
        if (isAttachedToWindow) updateAnimation()
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        if (isAttachedToWindow) updateAnimation()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val radius = minOf(width, height) / 2f - 12 * density
        ring.set(cx - radius, cy - radius, cx + radius, cy + radius)
        val animate = motionEnabled()

        when (state) {
            State.Halted -> {
                trackPaint.color = color(R.color.flow_ring_track)
                trackPaint.alpha = 255
                trackPaint.strokeWidth = 2 * density
                trackPaint.pathEffect = null
                canvas.drawOval(ring, trackPaint)
            }

            State.Running -> {
                val okColor = color(R.color.flow_connected)
                val wave = if (animate) {
                    (1 - kotlin.math.cos(2 * PI * elapsedMs / 2800.0).toFloat()) / 2
                } else {
                    0.5f
                }
                haloPaint.color = okColor
                haloPaint.alpha = (255 * (0.18f + 0.24f * wave)).toInt()
                val scale = 1f + 0.035f * wave
                canvas.save()
                canvas.scale(scale, scale, cx, cy)
                canvas.drawOval(ring, haloPaint)
                canvas.restore()
                arcPaint.color = okColor
                canvas.drawOval(ring, arcPaint)
            }

            State.Connecting, State.Disconnecting, State.Reconnecting -> {
                val reconnecting = state == State.Reconnecting
                val accent = color(
                    if (reconnecting) R.color.flow_reconnecting else R.color.flow_primary,
                )
                trackPaint.color = accent
                if (reconnecting) {
                    trackPaint.strokeWidth = 3 * density
                    trackPaint.alpha = 90
                    trackPaint.pathEffect = dots
                } else {
                    trackPaint.strokeWidth = 4 * density
                    trackPaint.alpha = 40
                    trackPaint.pathEffect = null
                }
                canvas.drawOval(ring, trackPaint)

                val period = if (reconnecting) 2200f else 1250f
                val rotation = if (animate) (elapsedMs % period.toLong()) / period * 360f else 0f
                val sweep = if (animate) {
                    165f + 75f * sin(2 * PI * elapsedMs / 1600.0).toFloat()
                } else {
                    140f
                }
                arcPaint.color = accent
                canvas.drawArc(ring, rotation - 90f, sweep, false, arcPaint)
            }
        }
    }
}
