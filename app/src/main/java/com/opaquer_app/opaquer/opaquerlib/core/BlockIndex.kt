package com.opaquer_app.opaquerlib.core

import java.security.SecureRandom

data class BlockIndex(
    val p0: Long, // most significant
    val p1: Long,
    val p2: Long,
    val p3: Long, // least significant
) : Comparable<BlockIndex> {

    // ULong comparison instead of java.lang.Long.compareUnsigned, which needs Android API 26
    override fun compareTo(other: BlockIndex): Int {
        p0.toULong().compareTo(other.p0.toULong()).let { if (it != 0) return it }
        p1.toULong().compareTo(other.p1.toULong()).let { if (it != 0) return it }
        p2.toULong().compareTo(other.p2.toULong()).let { if (it != 0) return it }
        return p3.toULong().compareTo(other.p3.toULong())
    }

    // word(0) = lowest 64 bits, word(3) = highest
    private fun word(i: Int): Long = when (i) {
        0 -> p3
        1 -> p2
        2 -> p1
        else -> p0
    }

    /** Reads 6 bits starting at bit offset [off] (0 = least significant bit). */
    private fun bits6(off: Int): Int {
        val w = off ushr 6
        val s = off and 63
        var v = word(w) ushr s
        if (s > 58 && w < 3) v = v or (word(w + 1) shl (64 - s)) // spans two words
        return (v and 63L).toInt()
    }

    /** 32 bytes, most significant first. Used as AEAD associated data and as HKDF info. */
    fun toBytes(): ByteArray {
        val out = ByteArray(BYTES)
        var i = 0
        for (w in longArrayOf(p0, p1, p2, p3)) {
            for (s in 56 downTo 0 step 8) out[i++] = (w ushr s).toByte()
        }
        return out
    }

    override fun toString(): String {
        val out = CharArray(LENGTH)
        for (i in 0 until LENGTH) {
            out[i] = ALPHABET[bits6(6 * (LENGTH - 1 - i))]
        }
        return String(out)
    }

    companion object {
        private const val ALPHABET =
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-"
        const val LENGTH = 43 // ceil(256 / 6)
        const val BYTES = 32

        private val DECODE = IntArray(128) { -1 }.also { table ->
            ALPHABET.forEachIndexed { i, c -> table[c.code] = i }
        }

        fun fromString(s: String): BlockIndex {
            require(s.length == LENGTH) { "Expected $LENGTH chars, got ${s.length}" }
            val words = LongArray(4) // lowest first
            for (i in 0 until LENGTH) {
                val c = s[i]
                val v = if (c.code < 128) DECODE[c.code] else -1
                require(v >= 0) { "Invalid character '$c' at index $i" }
                if (i == 0) require(v < 16) { "Value too large: first char must be one of ${ALPHABET.take(16)}" }

                val off = 6 * (LENGTH - 1 - i)
                val w = off ushr 6
                val sh = off and 63
                words[w] = words[w] or (v.toLong() shl sh)
                if (sh > 58 && w < 3) words[w + 1] = words[w + 1] or (v.toLong() ushr (64 - sh))
            }
            return BlockIndex(words[3], words[2], words[1], words[0])
        }

        fun fromBytes(b: ByteArray): BlockIndex {
            require(b.size == BYTES) { "Expected $BYTES bytes, got ${b.size}" }
            fun word(o: Int): Long {
                var v = 0L
                for (k in 0 until 8) v = (v shl 8) or (b[o + k].toLong() and 0xFF)
                return v
            }
            return BlockIndex(word(0), word(8), word(16), word(24))
        }

        fun random(random: SecureRandom): BlockIndex = fromBytes(ByteArray(BYTES).also { random.nextBytes(it) })
    }
}
