package io.github.dovecoteescapee.byedpi.views

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import io.github.dovecoteescapee.byedpi.R
import kotlin.math.PI
import kotlin.math.sin

/** A rotating arc around the connection button; the status text stays still. */
class ConnectionRingView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.flow_primary)
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeWidth = 3 * resources.displayMetrics.density
    }
    private val ring = RectF()
    private var phase = 0f
    private var busy = false
    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 1400
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener {
            phase = it.animatedValue as Float
            invalidate()
        }
    }

    fun setBusy(value: Boolean) {
        busy = value
        visibility = if (value) VISIBLE else INVISIBLE
        updateAnimation()
    }

    private fun updateAnimation() {
        if (busy && isAttachedToWindow && isShown && windowVisibility == VISIBLE) {
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
        if (!busy) return
        val radius = minOf(width, height) / 2f - paint.strokeWidth * 2
        ring.set(width / 2f - radius, height / 2f - radius,
            width / 2f + radius, height / 2f + radius)
        paint.alpha = 50
        canvas.drawOval(ring, paint)
        paint.alpha = 255
        val sweep = 85f + 35f * sin(phase * 2 * PI).toFloat()
        canvas.drawArc(ring, phase * 360f - 90f, sweep, false, paint)
        paint.alpha = 110
        canvas.drawArc(ring, phase * 360f + 90f, sweep / 2, false, paint)
    }
}
