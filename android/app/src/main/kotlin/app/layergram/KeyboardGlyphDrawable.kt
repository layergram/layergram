package app.layergram

import android.graphics.Canvas
import android.graphics.ColorFilter
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable

/** Monochrome icons, drawn locally without fonts, emoji or external assets. */
class KeyboardGlyphDrawable(private val glyph: String, color: Int, private val rim: Boolean = false) : Drawable() {
  private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
    this.color = color; strokeWidth = 1.8f; strokeCap = Paint.Cap.ROUND; strokeJoin = Paint.Join.ROUND
  }
  override fun draw(canvas: Canvas) {
    val side = minOf(bounds.width(), bounds.height()).toFloat()
    if (side <= 0f) return
    val saved = canvas.save()
    canvas.translate(bounds.left + (bounds.width() - side) / 2f, bounds.top + (bounds.height() - side) / 2f)
    canvas.scale(side / 24f, side / 24f)
    paint.style = Paint.Style.STROKE
    fun path(vararg points: Float) {
      val p = Path(); p.moveTo(points[0], points[1])
      for (i in 2 until points.size step 2) p.lineTo(points[i], points[i + 1])
      canvas.drawPath(p, paint)
    }
    when (glyph) {
      "contacts" -> {
        paint.style = Paint.Style.FILL
        canvas.drawCircle(12f, 7f, 4f, paint)
        canvas.drawRoundRect(4f, 13f, 20f, 22f, 5f, 5f, paint)
      }
      "paste" -> {
        canvas.drawRoundRect(8f, 3f, 20f, 21f, 2f, 2f, paint)
        canvas.drawRoundRect(3f, 8f, 15f, 22f, 2f, 2f, paint)
        path(10f, 6f, 15f, 6f)
      }
      "send" -> {
        path(2f, 9f, 21f, 2f, 14f, 19f, 9f, 13f, 2f, 9f)
        path(9f, 13f, 21f, 2f)
        // A contrasting badge keeps the lock distinct from the paper plane.
        val foreground = paint.color
        paint.style = Paint.Style.FILL; paint.color = if (foreground == -1) 0xFF0B5245.toInt() else 0xFF9ACBFA.toInt()
        canvas.drawCircle(17.5f, 18f, 6f, paint)
        paint.style = Paint.Style.STROKE; paint.color = foreground
        canvas.drawRoundRect(14f, 17f, 21f, 22f, 1f, 1f, paint)
        canvas.drawArc(15f, 13f, 20f, 20f, 180f, 180f, false, paint)
      }
      "shield" -> {
        val p = Path().apply {
          moveTo(12f, 2f); lineTo(21f, 6f); lineTo(21f, 13f)
          quadTo(21f, 19f, 12f, 23f); quadTo(3f, 19f, 3f, 13f)
          lineTo(3f, 6f); close()
        }
        paint.style = Paint.Style.FILL; canvas.drawPath(p, paint)
        if (rim) {
          val original = paint.color; paint.style = Paint.Style.STROKE
          paint.color = 0xFFFFC247.toInt(); canvas.drawPath(p, paint); paint.color = original
        }
      }
      "shift" -> path(12f, 3f, 22f, 13f, 16f, 13f, 16f, 22f, 8f, 22f, 8f, 13f, 2f, 13f, 12f, 3f)
      "delete" -> { path(8f, 5f, 22f, 5f, 22f, 20f, 8f, 20f, 2f, 12f, 8f, 5f); path(12f, 9f, 18f, 16f); path(18f, 9f, 12f, 16f) }
      "close" -> { path(5f, 5f, 19f, 19f); path(19f, 5f, 5f, 19f) }
      "return" -> path(21f, 4f, 21f, 14f, 3f, 14f, 8f, 9f, 3f, 14f, 8f, 19f)
      "emoji" -> {
        canvas.drawCircle(12f, 12f, 10f, paint)
        canvas.drawArc(6f, 7f, 18f, 18f, 20f, 140f, false, paint)
        paint.style = Paint.Style.FILL; canvas.drawCircle(8f, 8f, 1.2f, paint); canvas.drawCircle(16f, 8f, 1.2f, paint)
      }
    }
    canvas.restoreToCount(saved)
  }
  override fun setAlpha(alpha: Int) { paint.alpha = alpha }
  override fun setColorFilter(colorFilter: ColorFilter?) { paint.colorFilter = colorFilter }
  @Suppress("DEPRECATION") override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
}
