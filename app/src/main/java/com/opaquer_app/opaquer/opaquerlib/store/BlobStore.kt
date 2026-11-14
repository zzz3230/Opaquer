package com.opaquer_app.opaquerlib.store

import com.opaquer_app.opaquerlib.core.BlockIndex
import java.util.concurrent.ConcurrentHashMap

/**
 * The untrusted storage: a flat pool of equal-length blobs keyed by identifier.
 * Calls block; run them off the main thread.
 */
interface BlobStore {
    /**
     * Stores [data] under [id]. With [ifAbsent] the write must be atomic create-if-absent and returns
     * false when [id] already exists; the concurrency story of the archive rests on it.
     */
    fun put(id: BlockIndex, data: ByteArray, ifAbsent: Boolean = false): Boolean

    /** The blob, or null if it does not exist. */
    fun get(id: BlockIndex): ByteArray?

    /** Idempotent: deleting a missing blob succeeds. */
    fun delete(id: BlockIndex)

    fun exists(id: BlockIndex): Boolean

    /** Which of [ids] exist. Override when the backend can answer many at once. */
    fun existing(ids: Collection<BlockIndex>): Set<BlockIndex> = ids.filterTo(HashSet()) { exists(it) }
}

class InMemoryBlobStore : BlobStore {
    private val blobs = ConcurrentHashMap<BlockIndex, ByteArray>()

    val ids: Set<BlockIndex> get() = blobs.keys.toSet()

    override fun put(id: BlockIndex, data: ByteArray, ifAbsent: Boolean): Boolean {
        val copy = data.copyOf()
        if (ifAbsent) return blobs.putIfAbsent(id, copy) == null
        blobs[id] = copy
        return true
    }

    override fun get(id: BlockIndex): ByteArray? = blobs[id]?.copyOf()

    override fun delete(id: BlockIndex) {
        blobs.remove(id)
    }

    override fun exists(id: BlockIndex): Boolean = blobs.containsKey(id)
}
