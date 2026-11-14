package com.opaquer_app.opaquerlib.archive

import com.opaquer_app.opaquerlib.core.BlockIndex
import com.opaquer_app.opaquerlib.store.BlobStore

/**
 * Finds the newest user_data version without a fixed address.
 *
 * The last [window] versions always exist and are numbered without gaps, so they contain a multiple
 * of [window]. Phase 1 probes multiples of [window] and keeps the largest hit; phase 2 walks up from
 * it, where existence is monotone.
 */
class VersionLocator(
    private val store: BlobStore,
    private val window: Int,
    private val idOf: (Long) -> BlockIndex,
    private val maxSequenceNumber: Long,
) {
    /** Newest sequence number, or null if no version exists up to [maxSequenceNumber]. */
    fun findNewest(): Long? {
        var largestHit: Long? = null
        var first = 0L // index of the first multiple in the next batch
        var batchSize = INITIAL_BATCH
        while (first * window <= maxSequenceNumber) {
            val probes = (first until first + batchSize).map { it * window }.filter { it <= maxSequenceNumber }
            val hits = existing(probes)
            // A whole batch of misses above a hit: nothing more was written. Stopping at the first miss
            // instead would be fooled by a stale version that a failed delete left below the window.
            if (hits.isEmpty() && largestHit != null) break
            if (hits.isNotEmpty()) largestHit = hits.max()
            first += batchSize
            batchSize = minOf(batchSize * 2, MAX_BATCH)
        }
        return largestHit?.let(::walkUp)
    }

    /**
     * Search for a device that remembers [remembered]: one batch covering it and the next [window]
     * numbers. Falls back to [findNewest] when [remembered] is gone (the device fell more than a window
     * behind, or the storage lost data); the caller compares the result with [remembered].
     */
    fun findNewestFrom(remembered: Long): Long? {
        val hits = existing((remembered..remembered + window).toList())
        if (remembered !in hits) return findNewest()
        var newest = remembered
        while (newest + 1 in hits) newest++
        return if (newest == remembered + window) walkUp(newest) else newest
    }

    /** Largest n ≥ [start] with start..n all present; [start] is known to exist. */
    private fun walkUp(start: Long): Long {
        var newest = start
        while (true) {
            val before = newest
            val hits = existing((before + 1..before + window).toList())
            while (newest + 1 in hits) newest++
            if (newest < before + window) return newest
        }
    }

    private fun existing(seqs: List<Long>): Set<Long> {
        val bySeq = seqs.associateBy(idOf)
        return store.existing(bySeq.keys).mapTo(HashSet()) { bySeq.getValue(it) }
    }

    private companion object {
        const val INITIAL_BATCH = 256
        const val MAX_BATCH = 4096
    }
}
