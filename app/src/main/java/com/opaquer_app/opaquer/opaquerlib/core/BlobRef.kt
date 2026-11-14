package com.opaquer_app.opaquerlib.core

/**
 * Names one object inside a blob.
 *
 * Text form: "#<block-id | this for the current one>/<object id>:<length>",
 * for example "#this/0:1024" or "#000000000ji000000005yU0000008Hve0000000O8oc/6:654322".
 *
 * [Local] points into the object table of the user_data block that holds the reference, so it stays
 * valid when that block is republished under a new address. [Remote] points into a pack blob.
 * No key travels in either form: a blob's key follows from its identifier.
 */
sealed class BlobRef {
    abstract val objectId: Int
    abstract val length: Int

    data class Local(override val objectId: Int, override val length: Int) : BlobRef() {
        init {
            require(objectId >= 0 && length >= 0) { "Negative object id or length" }
        }
    }

    data class Remote(val block: BlockIndex, override val objectId: Int, override val length: Int) : BlobRef() {
        init {
            require(objectId >= 0 && length >= 0) { "Negative object id or length" }
        }
    }

    final override fun toString(): String {
        val blockText = when (this) {
            is Local -> THIS
            is Remote -> this.block.toString()
        }
        return "#$blockText/$objectId:$length"
    }

    companion object {
        const val THIS = "this"

        fun parse(s: String): BlobRef {
            val slash = s.indexOf('/')
            val colon = s.lastIndexOf(':')
            require(s.startsWith("#") && slash > 1 && colon > slash + 1 && colon < s.length - 1) {
                "Malformed reference '$s'"
            }
            val block = s.substring(1, slash)
            val objectId = s.substring(slash + 1, colon).toIntOrNull()
            val length = s.substring(colon + 1).toIntOrNull()
            require(objectId != null && length != null) { "Malformed reference '$s'" }
            return if (block == THIS) Local(objectId, length) else Remote(BlockIndex.fromString(block), objectId, length)
        }
    }
}

internal fun ByteWriter.blobRef(ref: BlobRef) {
    when (ref) {
        is BlobRef.Local -> u8(0)
        is BlobRef.Remote -> {
            u8(1)
            blockIndex(ref.block)
        }
    }
    i32(ref.objectId)
    i32(ref.length)
}

internal fun ByteReader.blobRef(): BlobRef {
    val kind = u8()
    val block = when (kind) {
        0 -> null
        1 -> blockIndex()
        else -> throw FormatException("Unknown reference kind $kind")
    }
    val objectId = i32()
    val length = i32()
    if (objectId < 0 || length < 0) throw FormatException("Negative object id or length")
    return if (block == null) BlobRef.Local(objectId, length) else BlobRef.Remote(block, objectId, length)
}
