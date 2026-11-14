package com.opaquer_app.opaquerlib.archive

import com.opaquer_app.opaquerlib.core.ArchiveNotFoundException
import com.opaquer_app.opaquerlib.core.ArchivePaths
import com.opaquer_app.opaquerlib.core.BlobRef
import com.opaquer_app.opaquerlib.core.BlobType
import com.opaquer_app.opaquerlib.core.BlockIndex
import com.opaquer_app.opaquerlib.core.BlockType
import com.opaquer_app.opaquerlib.core.CapacityException
import com.opaquer_app.opaquerlib.core.ConflictException
import com.opaquer_app.opaquerlib.core.DataBlock
import com.opaquer_app.opaquerlib.core.DataBlockBuilder
import com.opaquer_app.opaquerlib.core.FormatException
import com.opaquer_app.opaquerlib.core.IntegrityException
import com.opaquer_app.opaquerlib.core.MissingBlobException
import com.opaquer_app.opaquerlib.core.PackKey
import com.opaquer_app.opaquerlib.core.PendingDelete
import com.opaquer_app.opaquerlib.core.RollbackException
import com.opaquer_app.opaquerlib.core.UserdataBlock
import com.opaquer_app.opaquerlib.core.UserdataCodec
import com.opaquer_app.opaquerlib.core.UserdataFile
import com.opaquer_app.opaquerlib.core.UserdataFilePreview
import com.opaquer_app.opaquerlib.core.UserdataHeader
import com.opaquer_app.opaquerlib.core.toHex
import com.opaquer_app.opaquerlib.crypto.BlobSealer
import com.opaquer_app.opaquerlib.crypto.CryptoSuite
import com.opaquer_app.opaquerlib.crypto.KEY_BYTES
import com.opaquer_app.opaquerlib.crypto.KeySchedule
import com.opaquer_app.opaquerlib.crypto.sha256
import com.opaquer_app.opaquerlib.store.BlobStore
import java.security.SecureRandom

/**
 * What a device keeps about the newest version it has seen. Persist it next to the root key and pass
 * it to [Archive.open]. Sequence numbers keep growing across password changes, so a mark stays valid.
 */
data class VersionMark(val sequenceNumber: Long, val hash: String)

class PreviewInput(val type: BlobType, val bytes: ByteArray)

data class FolderListing(val folders: List<String>, val files: List<UserdataFile>)

/**
 * One open archive: the newest user_data version plus the edits made since.
 *
 * Edits stay in memory until [publish], which turns the whole session into one new version.
 * File contents go into packs, previews ride inline in the user_data block until it runs out of
 * room. Not thread-safe; every call that touches the store blocks.
 */
class Archive private constructor(
    private val store: BlobStore,
    private val config: ArchiveConfig,
    private val random: SecureRandom,
    private val sealer: BlobSealer,
    private var keys: KeySchedule,
    private var published: UserdataBlock,
    private var publishedHash: String,
) {
    private data class FileKey(val path: String, val name: String)

    private class OpenPack(val id: BlockIndex, val builder: DataBlockBuilder)

    // Working state; BlobRef.Local ids index localObjects
    private val files = LinkedHashMap<FileKey, UserdataFile>()
    private val folders = LinkedHashSet<String>()
    private var localObjects = ArrayList<ByteArray>()
    // Keys of every pack the working state may reference, including packs made in this session
    private val packKeys = HashMap<BlockIndex, ByteArray>()
    private var dirty = false

    private var openPack: OpenPack? = null
    // Packs uploaded since the last publish; no published version references them yet
    private val uploadedPacks = HashSet<BlockIndex>()
    // Pending deletes that went through; left out of the next version
    private val confirmedDeletes = HashSet<BlockIndex>()
    private var packCache: Pair<BlockIndex, DataBlock>? = null

    init {
        loadWorkingState(published)
    }

    val containerName: String get() = published.header.containerName

    val mark: VersionMark get() = VersionMark(published.header.sequenceNumber, publishedHash)

    val hasUnpublishedChanges: Boolean get() = dirty

    /** Largest file content, or preview, that fits into one block. */
    val maxFileSize: Int get() = (sealer.payloadCapacity - DataBlock.encodedSize(1, 0)).toInt()

    fun files(): List<UserdataFile> = files.values.sortedWith(FILE_ORDER)

    fun find(path: String, name: String): UserdataFile? = files[key(path, name)]

    fun list(folder: String = ArchivePaths.ROOT): FolderListing {
        val parent = ArchivePaths.folder(folder)
        val children = sortedSetOf<String>()
        for (p in folders.asSequence() + files.values.asSequence().map { it.path }) {
            ArchivePaths.childOf(parent, p)?.let(children::add)
        }
        return FolderListing(children.toList(), files.values.filter { it.path == parent }.sortedBy { it.name })
    }

    fun read(path: String, name: String): ByteArray = readObject(requireFile(path, name).blobRef)

    fun readPreview(path: String, name: String): ByteArray? =
        requireFile(path, name).preview?.let { readObject(it.blobRef) }

    /** Adds the file, or replaces its content if it exists. Replacing keeps createdAt. */
    fun put(
        path: String,
        name: String,
        type: BlobType,
        content: ByteArray,
        preview: PreviewInput? = null,
        note: String? = null,
        now: Long = System.currentTimeMillis(),
    ): UserdataFile {
        val k = key(path, name)
        if (content.size > maxFileSize) {
            throw CapacityException("File of ${content.size} bytes exceeds the $maxFileSize byte limit")
        }
        if (preview != null && preview.bytes.size > maxFileSize) {
            throw CapacityException("Preview of ${preview.bytes.size} bytes exceeds the $maxFileSize byte limit")
        }
        val contentRef = addToPack(content)
        val previewRef = preview?.let { UserdataFilePreview(addLocal(it.bytes), it.type) }
        val file = UserdataFile(k.path, k.name, note, type, files[k]?.createdAt ?: now, now, contentRef, previewRef)
        files[k] = file
        dirty = true
        return file
    }

    fun delete(path: String, name: String): Boolean =
        (files.remove(key(path, name)) != null).also { if (it) dirty = true }

    fun move(path: String, name: String, newPath: String, newName: String): UserdataFile {
        val from = key(path, name)
        val to = key(newPath, newName)
        val file = files[from] ?: throw NoSuchElementException("No file $path/$name")
        if (from == to) return file
        require(to !in files) { "A file ${to.path}/${to.name} already exists" }
        files.remove(from)
        return file.copy(path = to.path, name = to.name).also {
            files[to] = it
            dirty = true
        }
    }

    fun createFolder(path: String) {
        val p = ArchivePaths.folder(path)
        if (p != ArchivePaths.ROOT && folders.add(p)) dirty = true
    }

    /** Removes the explicit folder entry. Files below it, and the folders they imply, stay. */
    fun removeFolder(path: String): Boolean =
        folders.remove(ArchivePaths.folder(path)).also { if (it) dirty = true }

    /**
     * Publishes the session as the next version and returns its mark.
     *
     * Order: upload packs, create the user_data version if absent, then delete the version that
     * left the window, then the blobs that only it could reach. A failure before the create leaves
     * unreferenced blobs only; calling [publish] again retries with the same sequence number.
     */
    fun publish(): VersionMark {
        if (!dirty) return mark
        val seq = published.header.sequenceNumber + 1

        // Fit everything into one user_data block; previews leave first, oldest first
        var (next, payload) = build(seq)
        while (payload.size > sealer.payloadCapacity) {
            if (!spillPreviews(payload.size - sealer.payloadCapacity)) {
                throw CapacityException("The file index no longer fits into one block")
            }
            val rebuilt = build(seq)
            next = rebuilt.first
            payload = rebuilt.second
        }

        // Upload the last pack, unless nothing in it survived the session
        val lastPack = openPack
        if (lastPack != null) {
            if (lastPack.id in remoteBlocks(next.files)) flushPack() else openPack = null
        }

        val blob = putUserdata(store, sealer, keys, seq, payload)
        published = next
        publishedHash = sha256(blob).toHex()
        uploadedPacks.clear()
        confirmedDeletes.clear()
        loadWorkingState(next)
        collectGarbage(seq)
        return mark
    }

    /**
     * Moves the archive to the address space of [newRootKey], from [Archive.deriveRootKey] with the
     * new password. Only the user_data block is rewritten: pack keys live inside it, so no pack changes.
     *
     * The first new version takes the next multiple of the window, so it is found by the search and
     * sequence numbers keep growing. The old versions are deleted right away; devices that still hold
     * the old root key find no archive and have to ask for the password again.
     */
    fun changePassword(newRootKey: ByteArray): VersionMark {
        check(!dirty) { "Publish pending changes before changing the password" }
        val newKeys = KeySchedule(newRootKey)
        val oldKeys = keys
        val oldSeq = published.header.sequenceNumber
        val window = config.versionWindow
        require(newKeys.userdataId(oldSeq) != oldKeys.userdataId(oldSeq)) { "The new password gives the same root key" }

        val seq = (oldSeq / window + 1) * window
        val oldVersions = (maxOf(0, oldSeq - window + 1)..oldSeq).map { oldKeys.userdataId(it) }
        // Nothing in the new address space reaches these, so all are eligible at once (droppedAt 0)
        val carried = (published.deletes.map { it.block } + oldVersions).distinct().map { PendingDelete(it, 0) }
        val next = published.copy(header = UserdataHeader(containerName, seq, publishedHash), deletes = carried)

        val blob = putUserdata(store, sealer, newKeys, seq, UserdataCodec.encode(next))
        keys = newKeys
        published = next
        publishedHash = sha256(blob).toHex()
        confirmedDeletes.clear()
        loadWorkingState(next)

        // Old versions first: the old packs in the queue may still be referenced by them
        if (oldVersions.all(::tryDelete)) {
            for (d in carried) if (tryDelete(d.block)) confirmedDeletes += d.block
        }
        return mark
    }

    private fun build(seq: Long): Pair<UserdataBlock, ByteArray> {
        // Repack the inline objects that are still referenced, renumbering their local ids
        val objects = DataBlockBuilder(Long.MAX_VALUE)
        val remap = HashMap<Int, Int>()
        fun relocate(ref: BlobRef): BlobRef = when (ref) {
            is BlobRef.Local -> BlobRef.Local(remap.getOrPut(ref.objectId) { objects.add(localObjects[ref.objectId]) }, ref.length)
            is BlobRef.Remote -> ref
        }
        val nextFiles = files.values.sortedWith(FILE_ORDER).map { f ->
            f.copy(blobRef = relocate(f.blobRef), preview = f.preview?.let { it.copy(blobRef = relocate(it.blobRef)) })
        }

        val window = config.versionWindow
        val nextPacks = remoteBlocks(nextFiles)
        val dropped = ((remoteBlocks(published.files) + uploadedPacks) - nextPacks).sorted()
        val deletes = published.deletes.filter { it.block !in confirmedDeletes } +
            dropped.map { PendingDelete(it, seq) } +
            // The version leaving the window is queued too, so a failed delete is retried later
            listOfNotNull((seq - window).takeIf { it >= 0 }?.let { PendingDelete(keys.userdataId(it), it + 1) })

        val block = UserdataBlock(
            header = UserdataHeader(containerName, seq, publishedHash),
            files = nextFiles,
            folders = folders.sorted(),
            deletes = deletes.distinctBy { it.block },
            packKeys = nextPacks.sorted().map { PackKey(it, packKeys.getValue(it)) },
            objects = objects.build(),
        )
        return block to UserdataCodec.encode(block)
    }

    /** Moves inline previews into packs, oldest first, until about [overflow] bytes are freed. */
    private fun spillPreviews(overflow: Int): Boolean {
        val candidates = files.values.filter { it.preview?.blobRef is BlobRef.Local }.sortedBy { it.createdAt }
        if (candidates.isEmpty()) return false
        var freed = 0L
        for (file in candidates) {
            if (freed >= overflow) break
            val preview = file.preview!!
            val ref = preview.blobRef
            files[FileKey(file.path, file.name)] =
                file.copy(preview = preview.copy(blobRef = addToPack(localObjects[ref.objectId])))
            // A local ref becomes a remote one (+32 bytes) plus a pack key entry (+64 bytes, shared)
            freed += ref.length + DataBlock.ENTRY_BYTES - BlockIndex.BYTES
        }
        return true
    }

    /**
     * Runs after version [seq] is published. A blob dropped at d is still reachable from d-1, so it may
     * go only once d-1 has left the window, which needs the version that just expired to be gone first.
     * Failures stay queued for the next publish: a missed delete only widens the window.
     */
    private fun collectGarbage(seq: Long) {
        val expired = seq - config.versionWindow
        if (expired >= 0 && !tryDelete(keys.userdataId(expired))) return
        for (d in published.deletes) {
            if (d.droppedAt <= expired + 1 && tryDelete(d.block)) confirmedDeletes += d.block
        }
    }

    private fun tryDelete(id: BlockIndex): Boolean =
        try {
            store.delete(id)
            true
        } catch (e: Exception) {
            false
        }

    private fun addLocal(bytes: ByteArray): BlobRef.Local {
        localObjects.add(bytes.copyOf())
        return BlobRef.Local(localObjects.size - 1, bytes.size)
    }

    private fun addToPack(bytes: ByteArray): BlobRef.Remote {
        openPack?.let { if (!it.builder.fits(bytes.size)) flushPack() }
        val pack = openPack ?: newPack().also { openPack = it }
        return BlobRef.Remote(pack.id, pack.builder.add(bytes), bytes.size)
    }

    private fun newPack(): OpenPack {
        val id = BlockIndex.random(random)
        packKeys[id] = newKey(random)
        return OpenPack(id, DataBlockBuilder(sealer.payloadCapacity.toLong()))
    }

    private fun flushPack() {
        val pack = openPack ?: return
        if (!pack.builder.isEmpty) {
            val blob = sealer.seal(pack.id, packKeys.getValue(pack.id), BlockType.DATA, pack.builder.build().encode())
            if (!store.put(pack.id, blob, ifAbsent = true)) throw ConflictException("Blob ${pack.id} already exists")
            uploadedPacks += pack.id
        }
        openPack = null
    }

    private fun readObject(ref: BlobRef): ByteArray {
        val bytes = when (ref) {
            is BlobRef.Local -> localObjects.getOrNull(ref.objectId)?.copyOf()
                ?: throw FormatException("Inline object ${ref.objectId} out of range")
            is BlobRef.Remote -> openPack?.takeIf { it.id == ref.block }?.builder?.get(ref.objectId)
                ?: loadPack(ref.block)[ref.objectId]
        }
        if (bytes.size != ref.length) throw FormatException("Object length does not match its reference")
        return bytes
    }

    private fun loadPack(id: BlockIndex): DataBlock {
        packCache?.let { (cachedId, block) -> if (cachedId == id) return block }
        val key = packKeys[id] ?: throw FormatException("No key for pack $id")
        val blob = store.get(id) ?: throw MissingBlobException(id, "Blob $id is missing")
        val decoded = sealer.open(id, key, blob)
        if (decoded.type != BlockType.DATA) throw FormatException("Blob $id is not a pack")
        return DataBlock.decode(decoded.payload).also { packCache = id to it }
    }

    private fun loadWorkingState(block: UserdataBlock) {
        files.clear()
        block.files.forEach { files[FileKey(it.path, it.name)] = it }
        folders.clear()
        folders.addAll(block.folders)
        localObjects = ArrayList<ByteArray>(block.objects.size).apply {
            for (i in 0 until block.objects.size) add(block.objects[i])
        }
        packKeys.clear()
        block.packKeys.forEach { packKeys[it.block] = it.key }
        dirty = false
    }

    private fun requireFile(path: String, name: String): UserdataFile =
        find(path, name) ?: throw NoSuchElementException("No file $path/$name")

    private fun key(path: String, name: String) = FileKey(ArchivePaths.folder(path), ArchivePaths.name(name))

    companion object {
        private val FILE_ORDER = compareBy<UserdataFile>({ it.path }, { it.name })

        /** A fresh random 32-byte key. Use it for the cold key. */
        fun newKey(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(KEY_BYTES).also { random.nextBytes(it) }

        /**
         * Root key from the two secrets. Runs Argon2id, so it is slow on purpose: call it once on a new
         * device and keep the result in the platform keystore.
         */
        fun deriveRootKey(crypto: CryptoSuite, coldKey: ByteArray, password: CharArray): ByteArray =
            KeySchedule.deriveRootKey(coldKey, password, crypto.passwordKdf)

        /** Creates an empty archive: version 0 at the addresses of [rootKey]. */
        fun create(
            store: BlobStore,
            crypto: CryptoSuite,
            rootKey: ByteArray,
            containerName: String = "",
            config: ArchiveConfig = ArchiveConfig(),
        ): Archive {
            val sealer = BlobSealer(crypto.aead, crypto.random, config.blockSize)
            val keys = KeySchedule(rootKey)
            // Version 0 is gone once the archive has more than a window of saves, so search instead
            if (VersionLocator(store, config.versionWindow, keys::userdataId, config.maxSequenceNumber).findNewest() != null) {
                throw ConflictException("An archive already exists for this cold key and password")
            }
            val first = UserdataBlock(
                header = UserdataHeader(containerName, 0, UserdataHeader.ZERO_HASH),
                files = emptyList(),
                folders = emptyList(),
                deletes = emptyList(),
                packKeys = emptyList(),
                objects = DataBlock.EMPTY,
            )
            val blob = putUserdata(store, sealer, keys, 0, UserdataCodec.encode(first))
            return Archive(store, config, crypto.random, sealer, keys, first, sha256(blob).toHex())
        }

        /**
         * Opens the newest version. With [remembered] the search is one batch, and the storage may not
         * serve anything older than, or different from, what this device has already seen.
         * Throws [ArchiveNotFoundException] when nothing exists at the addresses of [rootKey].
         */
        fun open(
            store: BlobStore,
            crypto: CryptoSuite,
            rootKey: ByteArray,
            remembered: VersionMark? = null,
            config: ArchiveConfig = ArchiveConfig(),
        ): Archive {
            val sealer = BlobSealer(crypto.aead, crypto.random, config.blockSize)
            val keys = KeySchedule(rootKey)
            val locator = VersionLocator(store, config.versionWindow, keys::userdataId, config.maxSequenceNumber)

            repeat(3) {
                val seq = (if (remembered == null) locator.findNewest() else locator.findNewestFrom(remembered.sequenceNumber))
                    ?: throw ArchiveNotFoundException()
                if (remembered != null && seq < remembered.sequenceNumber) {
                    throw RollbackException("Storage serves version $seq, this device has seen ${remembered.sequenceNumber}")
                }
                val id = keys.userdataId(seq)
                // A save between the search and the download can delete the version found: search again
                val blob = store.get(id) ?: return@repeat
                val decoded = sealer.open(id, keys.userdataBlobKey(id), blob)
                if (decoded.type != BlockType.USERDATA) throw FormatException("Blob at version $seq is not user_data")
                val block = UserdataCodec.decode(decoded.payload)
                if (block.header.sequenceNumber != seq) {
                    throw IntegrityException("Version $seq carries sequence number ${block.header.sequenceNumber}")
                }
                checkPackKeys(block)
                val hash = sha256(blob).toHex()
                if (remembered != null) checkHistory(remembered, block, hash)
                return Archive(store, config, crypto.random, sealer, keys, block, hash)
            }
            throw MissingBlobException(null, "The newest user_data version kept disappearing")
        }

        /** Seals and creates user_data [seq]; returns the stored blob. */
        private fun putUserdata(store: BlobStore, sealer: BlobSealer, keys: KeySchedule, seq: Long, payload: ByteArray): ByteArray {
            val id = keys.userdataId(seq)
            val key = keys.userdataBlobKey(id)
            val blob = sealer.seal(id, key, BlockType.USERDATA, payload)
            if (store.put(id, blob, ifAbsent = true)) return blob
            // A retry after a lost response finds its own earlier upload there
            val existing = store.get(id)
            val ours = existing != null &&
                runCatching { sealer.open(id, key, existing).payload.contentEquals(payload) }.getOrDefault(false)
            if (!ours) throw ConflictException("Version $seq was published by another writer; reopen the archive")
            return existing!!
        }

        private fun checkPackKeys(block: UserdataBlock) {
            val known = block.packKeys.mapTo(HashSet()) { it.block }
            val missing = remoteBlocks(block.files) - known
            if (missing.isNotEmpty()) throw FormatException("No key for ${missing.size} referenced pack(s)")
        }

        private fun checkHistory(remembered: VersionMark, block: UserdataBlock, hash: String) {
            when (block.header.sequenceNumber) {
                remembered.sequenceNumber -> if (hash != remembered.hash) {
                    throw RollbackException("Version ${remembered.sequenceNumber} differs from the one this device saw")
                }
                remembered.sequenceNumber + 1 -> if (block.header.previousHash != remembered.hash) {
                    throw RollbackException("Version ${block.header.sequenceNumber} does not follow the one this device saw")
                }
            }
        }

        private fun remoteBlocks(files: Collection<UserdataFile>): Set<BlockIndex> =
            files.flatMap { listOfNotNull(it.blobRef, it.preview?.blobRef) }
                .filterIsInstance<BlobRef.Remote>()
                .mapTo(HashSet()) { it.block }
    }
}
