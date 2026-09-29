package app.layergram

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.view.MotionEvent
import android.widget.TextView

/** A local text viewport with a visible caret; it never opens another IME. */
class KeyboardDraftView(context: Context) : TextView(context) {
  var localCursor = 0
  var onCursorTouch: ((Int) -> Unit)? = null
  private val caret = Paint(Paint.ANTI_ALIAS_FLAG)
  init {
    isFocusable = false
    isSaveEnabled = false
    setTextIsSelectable(false)
    isVerticalScrollBarEnabled = false
  }
  override fun onCheckIsTextEditor(): Boolean = false
  fun present(value: String, cursor: Int) {
    if (text.toString() != value) text = value
    localCursor = cursor.coerceIn(0, value.length)
    post { keepCursorVisible(); invalidate() }
  }
  fun offsetAt(x: Float, y: Float): Int {
    val textLayout = layout ?: return 0
    val line = textLayout.getLineForVertical((y - totalPaddingTop + scrollY).toInt().coerceAtLeast(0))
    return textLayout.getOffsetForHorizontal(line, x - totalPaddingLeft + scrollX)
  }
  fun moveVertical(lines: Int): Int {
    val textLayout = layout ?: return localCursor
    val line = textLayout.getLineForOffset(localCursor)
    return textLayout.getOffsetForHorizontal((line + lines).coerceIn(0, textLayout.lineCount - 1),
      textLayout.getPrimaryHorizontal(localCursor))
  }
  private fun keepCursorVisible() {
    val textLayout = layout ?: return
    val line = textLayout.getLineForOffset(localCursor)
    val top = textLayout.getLineTop(line)
    val bottom = textLayout.getLineBottom(line)
    val viewport = height - totalPaddingTop - totalPaddingBottom
    if (viewport <= 0) return
    val target = when { top < scrollY -> top; bottom > scrollY + viewport -> bottom - viewport; else -> scrollY }
    scrollTo(0, target.coerceAtLeast(0))
  }
  override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)
    val textLayout = layout ?: return
    caret.color = currentTextColor
    caret.strokeWidth = 2 * resources.displayMetrics.density
    val line = textLayout.getLineForOffset(localCursor)
    val x = textLayout.getPrimaryHorizontal(localCursor) + totalPaddingLeft
    canvas.drawLine(x, (textLayout.getLineTop(line) + totalPaddingTop).toFloat(),
      x, (textLayout.getLineBottom(line) + totalPaddingTop).toFloat(), caret)
  }
  override fun onTouchEvent(event: MotionEvent): Boolean {
    if (event.actionMasked == MotionEvent.ACTION_DOWN || event.actionMasked == MotionEvent.ACTION_MOVE) {
      onCursorTouch?.invoke(offsetAt(event.x, event.y))
    }
    if (event.actionMasked == MotionEvent.ACTION_UP) performClick()
    return true
  }
  override fun performClick(): Boolean { super.performClick(); return true }
}
