package com.opaquer_app.opaquerlib.core


/** MIME type of a file or preview, for example "image/jpeg". */
typealias BlobType = String


data class UserdataHeader(
    val containerName: String,
    val sequenceNumber: Long,
    // Hex SHA-256 of the previous version's stored blob; ZERO_HASH for version 0
    val previousHash: String,
) {
    init {
        require(sequenceNumber >= 0) { "Negative sequence number" }
        require(previousHash.length == 64 && previousHash.all { it in '0'..'9' || it in 'a'..'f' }) {
            "previousHash must be 64 lowercase hex digits"
        }
    }

    companion object {
        val ZERO_HASH = "0".repeat(64)
    }
}

data class UserdataFilePreview(
    val blobRef: BlobRef,
    val type: BlobType,
)

data class UserdataFile(
    val path: String,
    val name: String,
    val note: String?,
    val type: BlobType,
    val createdAt: Long,
    val updatedAt: Long,
    val blobRef: BlobRef,
    val preview: UserdataFilePreview?
) {
    val size: Int get() = blobRef.length
}

/**
 * A blob waiting for deletion. It was dropped in version [droppedAt] and is still reachable from
 * version droppedAt - 1, so it may go once that version has left the window.
 */
data class PendingDelete(
    val block: BlockIndex,
    val droppedAt: Long,
)

/** Random key of one pack. Each version lists the keys of exactly the packs it references. */
class PackKey(
    val block: BlockIndex,
    val key: ByteArray,
) {
    override fun equals(other: Any?): Boolean = other is PackKey && block == other.block && key.contentEquals(other.key)

    override fun hashCode(): Int = 31 * block.hashCode() + key.contentHashCode()

    override fun toString(): String = "PackKey($block)"
}

data class UserdataBlock(
    val header: UserdataHeader,
    val files: List<UserdataFile>,
    // Explicitly created folders; folders that hold files are also implied by file paths
    val folders: List<String>,
    val deletes: List<PendingDelete>,
    val packKeys: List<PackKey>,
    // Objects that BlobRef.Local points at: inline previews
    val objects: DataBlock
)
