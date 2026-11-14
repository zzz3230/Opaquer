package com.opaquer_app.opaquerlib.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HKDF-SHA-256 (RFC 5869). */
object Hkdf {
    private const val HASH_BYTES = 32

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray =
        hmacSha256(salt?.takeIf { it.isNotEmpty() } ?: ByteArray(HASH_BYTES), ikm)

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_BYTES) { "Invalid HKDF output length $length" }
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            t = hmacSha256(prk, t, info, byteArrayOf(counter.toByte()))
            val n = minOf(HASH_BYTES, length - pos)
            t.copyInto(out, pos, 0, n)
            pos += n
            counter++
        }
        return out
    }

    fun derive(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray =
        expand(extract(salt, ikm), info, length)
}

internal fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    for (p in parts) mac.update(p)
    return mac.doFinal()
}

internal fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

internal fun label(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
