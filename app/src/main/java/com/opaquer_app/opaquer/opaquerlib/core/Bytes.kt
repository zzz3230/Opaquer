package com.opaquer_app.opaquerlib.core

import java.io.ByteArrayOutputStream

/** Big-endian writer used by every on-storage structure. */
internal class ByteWriter {
    private val out = ByteArrayOutputStream()

    fun u8(v: Int) = out.write(v)

    fun i32(v: Int) {
        out.write(v ushr 24)
        out.write(v ushr 16)
        out.write(v ushr 8)
        out.write(v)
    }

    fun i64(v: Long) {
        i32((v ushr 32).toInt())
        i32(v.toInt())
    }

    fun bytes(b: ByteArray) = out.write(b, 0, b.size)

    fun string(s: String) {
        val b = s.toByteArray(Charsets.UTF_8)
        i32(b.size)
        bytes(b)
    }

    fun nullableString(s: String?) {
        if (s == null) u8(0) else {
            u8(1)
            string(s)
        }
    }

    fun blockIndex(id: BlockIndex) = bytes(id.toBytes())

    fun toByteArray(): ByteArray = out.toByteArray()
}

/** Counterpart of [ByteWriter]. Every malformed input ends in [FormatException]. */
internal class ByteReader(private val buf: ByteArray) {
    private var pos = 0

    val remaining: Int get() = buf.size - pos

    private fun take(n: Int): Int {
        if (n < 0 || n > remaining) throw FormatException("Unexpected end of data")
        return pos.also { pos += n }
    }

    fun u8(): Int = buf[take(1)].toInt() and 0xFF

    fun i32(): Int {
        val p = take(4)
        return ((buf[p].toInt() and 0xFF) shl 24) or
            ((buf[p + 1].toInt() and 0xFF) shl 16) or
            ((buf[p + 2].toInt() and 0xFF) shl 8) or
            (buf[p + 3].toInt() and 0xFF)
    }

    fun i64(): Long = (i32().toLong() shl 32) or (i32().toLong() and 0xFFFFFFFFL)

    fun bytes(n: Int): ByteArray {
        val p = take(n)
        return buf.copyOfRange(p, p + n)
    }

    fun string(): String = bytes(i32()).toString(Charsets.UTF_8)

    fun flag(): Boolean = when (u8()) {
        0 -> false
        1 -> true
        else -> throw FormatException("Invalid flag")
    }

    fun nullableString(): String? = if (flag()) string() else null

    fun blockIndex(): BlockIndex = BlockIndex.fromBytes(bytes(BlockIndex.BYTES))

    /** Reads a list length, rejecting counts that the remaining bytes cannot hold. */
    fun count(minElementBytes: Int): Int {
        val n = i32()
        if (n < 0 || n.toLong() * minElementBytes > remaining) throw FormatException("Invalid element count $n")
        return n
    }

    fun expectEnd() {
        if (remaining != 0) throw FormatException("$remaining bytes of trailing data")
    }
}

private const val HEX = "0123456789abcdef"

internal fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        sb.append(HEX[v ushr 4]).append(HEX[v and 15])
    }
    return sb.toString()
}

internal fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "Odd number of hex digits" }
    return ByteArray(length / 2) { i -> ((hexDigit(this[2 * i]) shl 4) or hexDigit(this[2 * i + 1])).toByte() }
}

private fun hexDigit(c: Char): Int = Character.digit(c, 16).also { require(it >= 0) { "Invalid hex digit '$c'" } }

internal fun Long.toBytes(): ByteArray = ByteArray(8) { i -> (this ushr (56 - 8 * i)).toByte() }
