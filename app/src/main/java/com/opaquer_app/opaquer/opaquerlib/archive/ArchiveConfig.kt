package com.opaquer_app.opaquerlib.archive

/**
 * Format parameters. [blockSize] and [versionWindow] must be the same on every device that opens
 * the archive; changing them later rewrites the archive.
 */
data class ArchiveConfig(
    // Length of every stored blob
    val blockSize: Int = 4 * 1024 * 1024,
    // K: how many user_data versions are kept
    val versionWindow: Int = 64,
    // Upper bound for the cold-start search. A wrong password probes every multiple of
    // versionWindow up to here before giving up, so it also bounds that cost.
    val maxSequenceNumber: Long = 1_000_000,
) {
    init {
        require(blockSize >= 1024) { "Block size must be at least 1 KiB" }
        require(versionWindow >= 2) { "Version window must be at least 2" }
        require(maxSequenceNumber >= 0) { "Negative maxSequenceNumber" }
    }
}
