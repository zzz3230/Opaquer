package com.opaquer_app.opaquerlib.crypto

import com.opaquer_app.opaquerlib.core.BlockIndex
import com.opaquer_app.opaquerlib.core.BlockType
import com.opaquer_app.opaquerlib.core.CapacityException
import com.opaquer_app.opaquerlib.core.DecodedBlock
import com.opaquer_app.opaquerlib.core.FormatException
import com.opaquer_app.opaquerlib.core.IntegrityException
import java.security.SecureRandom

/**
 * Turns payloads into blobs of exactly [blockSize] bytes and back.
 *
 * ```
 * blob      = nonce || AEAD(key, nonce, plaintext, ad = blob id)
 * plaintext = format version (1B) || type (1B) || used length (4B) || payload || zero padding
 * ```
 * Padding sits inside the encryption, so every blob is the same length of uniform-looking bytes.
 */
class BlobSealer(private val aead: Aead, private val random: SecureRandom, val blockSize: Int) {
    private val plaintextSize = blockSize - aead.nonceSize - aead.tagSize
    val payloadCapacity = plaintextSize - HEADER_BYTES

    init {
        require(payloadCapacity > 0) { "Block size $blockSize is too small" }
    }

    fun seal(id: BlockIndex, key: ByteArray, type: BlockType, payload: ByteArray): ByteArray {
        if (payload.size > payloadCapacity) {
            throw CapacityException("Payload of ${payload.size} bytes exceeds the block capacity of $payloadCapacity")
        }
        val plaintext = ByteArray(plaintextSize)
        plaintext[0] = FORMAT_VERSION.toByte()
        plaintext[1] = type.code.toByte()
        for (i in 0 until 4) plaintext[2 + i] = (payload.size ushr (24 - 8 * i)).toByte()
        payload.copyInto(plaintext, HEADER_BYTES)

        val nonce = ByteArray(aead.nonceSize).also { random.nextBytes(it) }
        val sealed = aead.seal(key, nonce, plaintext, id.toBytes())
        plaintext.fill(0)
        return nonce + sealed
    }

    fun open(id: BlockIndex, key: ByteArray, blob: ByteArray): DecodedBlock {
        if (blob.size != blockSize) throw IntegrityException("Blob $id has length ${blob.size}, expected $blockSize")
        val n = aead.nonceSize
        val plaintext = aead.open(key, blob.copyOfRange(0, n), blob.copyOfRange(n, blob.size), id.toBytes())

        val version = plaintext[0].toInt() and 0xFF
        if (version != FORMAT_VERSION) throw FormatException("Unsupported format version $version")
        val type = BlockType.fromCode(plaintext[1].toInt() and 0xFF)
        var used = 0
        for (i in 0 until 4) used = (used shl 8) or (plaintext[2 + i].toInt() and 0xFF)
        if (used < 0 || used > payloadCapacity) throw FormatException("Invalid used length $used")

        return DecodedBlock(id, version, type, plaintext.copyOfRange(HEADER_BYTES, HEADER_BYTES + used))
    }

    companion object {
        const val FORMAT_VERSION = 1
        const val HEADER_BYTES = 6
    }
}
