package app.layergram

import java.text.BreakIterator
import java.text.Normalizer
import java.util.Locale

/** A hint only: contacts are parsed, fingerprinted and confirmed in the app. */
internal object KeyboardPastePolicy {
  fun looksLikePublicIdentity(text: String): Boolean {
    val normalized = text.trim()
    if (normalized.length > 4096) return false
    return normalized.startsWith("layergram://i/", ignoreCase = true) ||
      normalized.startsWith("v3.") || normalized.startsWith("[layergram identity]", ignoreCase = true)
  }
}

/** Local-only editor: neither its text nor its cursor belongs to the host field. */
class KeyboardComposerState(private val limit: Int = KeyboardEditorPolicy.MAX_COMPOSE_CODE_UNITS) {
  var text: String = ""
    private set
  var cursor: Int = 0
    private set

  fun insert(value: String): Boolean {
    if (text.length + value.length > limit) return false
    text = text.substring(0, cursor) + value + text.substring(cursor)
    cursor += value.length
    return true
  }

  fun moveTo(offset: Int) {
    val target = offset.coerceIn(0, text.length)
    val boundaries = boundaries()
    cursor = boundaries.minByOrNull { kotlin.math.abs(it - target) } ?: 0
  }

  fun moveBy(characters: Int) {
    val boundaries = boundaries()
    val index = boundaries.indexOf(cursor).coerceAtLeast(0)
    cursor = boundaries[(index + characters).coerceIn(0, boundaries.lastIndex)]
  }

  fun deleteBeforeCursor() {
    if (cursor == 0) return
    val previous = boundaries().last { it < cursor }
    text = text.removeRange(previous, cursor)
    cursor = previous
  }

  fun clear() { text = ""; cursor = 0 }

  private fun boundaries(): List<Int> {
    val iterator = BreakIterator.getCharacterInstance(Locale.ROOT)
    iterator.setText(text)
    val result = mutableListOf(0)
    var next = iterator.next()
    while (next != BreakIterator.DONE) {
      // Join combining marks, variation selectors, emoji modifiers and ZWJ
      // sequences even on older platform BreakIterator implementations.
      if (next == text.length || !joinsAt(next)) result.add(next)
      next = iterator.next()
    }
    return result
  }

  private fun joinsAt(offset: Int): Boolean {
    val next = text.codePointAt(offset)
    val previous = text.codePointBefore(offset)
    val type = Character.getType(next)
    if (next == 0x200D || previous == 0x200D || next in 0xFE00..0xFE0F ||
      next in 0x1F3FB..0x1F3FF || type == Character.NON_SPACING_MARK.toInt() ||
      type == Character.COMBINING_SPACING_MARK.toInt()) return true
    if (next in 0x1F1E6..0x1F1FF && previous in 0x1F1E6..0x1F1FF) {
      var count = 0
      var index = offset
      while (index > 0 && text.codePointBefore(index) in 0x1F1E6..0x1F1FF) {
        index -= Character.charCount(text.codePointBefore(index)); count++
      }
      return count % 2 == 1
    }
    return false
  }
}

/** Display policy shared by compose, chooser and the native regression tests. */
object KeyboardPresentation {
  fun letterRows(language: String): List<String> = when (language) {
    "es" -> listOf("qwertyuiop", "asdfghjklñ", "zxcvbnm")
    "de" -> listOf("qwertzuiopü", "asdfghjklöä", "yxcvbnm")
    "fr" -> listOf("azertyuiop", "qsdfghjklm", "wxcvbn")
    "pt" -> listOf("qwertyuiop", "asdfghjklç", "zxcvbnm")
    "sv" -> listOf("qwertyuiopå", "asdfghjklöä", "zxcvbnm")
    "no", "nb", "nn", "da" -> listOf("qwertyuiopå", "asdfghjkløæ", "zxcvbnm")
    else -> listOf("qwertyuiop", "asdfghjkl", "zxcvbnm")
  }

  fun variants(letter: String): List<String> {
    val lower = letter.lowercase(Locale.ROOT)
    val choices = when (lower) {
      "a" -> "aàáâäãåæā"
      "e" -> "eèéêëēėę"
      "i" -> "iìíîïīįı"
      "o" -> "oòóôöõøœō"
      "u" -> "uùúûüū"
      "c" -> "cçćč"
      "d" -> "dďđð"
      "g" -> "gğ"
      "n" -> "nñńň"
      "r" -> "rřŕ"
      "s" -> "sßśšşș"
      "t" -> "tťțþ"
      "z" -> "zźżž"
      "l" -> "lłľĺ"
      "y" -> "yýÿ"
      else -> return emptyList()
    }
    return choices.map { if (letter != lower) it.uppercaseChar().toString() else it.toString() }
  }

  fun matches(name: String, query: String): Boolean {
    fun fold(value: String) = Normalizer.normalize(value, Normalizer.Form.NFD)
      .replace(Regex("\\p{M}+"), "").lowercase(Locale.ROOT)
    return fold(name).contains(fold(query.trim()))
  }

  fun primaryAction(hasText: Boolean): String = if (hasText) "send" else "paste"

  val securityPhases = setOf("setupRequired", "setupPending", "normalActive", "maximumActive",
    "recoveryRequired", "maximumSetupRequired", "maximumSetupPending", "maximumRecoveryRequired")
  fun shieldState(phase: String?): String = when (phase) {
    "normalActive", "maximumActive" -> "active"
    "recoveryRequired", "maximumRecoveryRequired" -> "recovery"
    "setupRequired", "setupPending", "maximumSetupRequired", "maximumSetupPending" -> "pending"
    else -> "unknown"
  }
}

/** Real input renews inactivity. Rendering and heartbeats never do. */
class KeyboardInteractionWindow {
  private var duration = 0L
  private var deadline = 0L
  private var lastObserved = 0L
  fun start(now: Long, idleMillis: Int): Boolean {
    clear()
    if (now < 0 || idleMillis !in 1..300000) return false
    duration = idleMillis.toLong(); lastObserved = now; deadline = now + duration
    return true
  }
  fun remaining(now: Long): Long {
    if (now < lastObserved) { clear(); return 0 }
    lastObserved = now
    return if (duration == 0L) 0 else (deadline - now).coerceAtLeast(0)
  }
  fun touch(now: Long): Boolean {
    if (remaining(now) == 0L) return false
    deadline = now + duration
    return true
  }
  fun clear() { duration = 0; deadline = 0; lastObserved = 0 }
}

/** A late finger-up after a lifecycle clear cannot commit an old accent. */
class KeyboardAccentSelection {
  var options: List<String> = emptyList()
    private set
  var index = 0
    private set
  fun begin(values: List<String>) { options = values.toList(); index = 0 }
  fun move(target: Int) { if (options.isNotEmpty()) index = target.coerceIn(0, options.lastIndex) }
  fun finish(): String? = options.getOrNull(index).also { clear() }
  fun clear() { options = emptyList(); index = 0 }
}
