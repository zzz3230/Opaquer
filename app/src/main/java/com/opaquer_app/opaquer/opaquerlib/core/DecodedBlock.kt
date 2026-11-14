package com.opaquer_app.opaquerlib.core


/** Type byte inside the sealed plaintext. Never visible on the storage. */
enum class BlockType(val code: Int) {
    USERDATA(1),
    DATA(2);

    companion object {
        fun fromCode(code: Int): BlockType =
            entries.firstOrNull { it.code == code } ?: throw FormatException("Unknown block type $code")
    }
}

/** An opened blob: the plaintext header fields plus the used part of the payload. */
class DecodedBlock(
    val blockIndex: BlockIndex,
    val formatVersion: Int,
    val type: BlockType,
    val payload: ByteArray
)
