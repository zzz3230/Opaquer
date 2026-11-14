package com.opaquer_app.opaquerlib.core

/** Binary encoding of [UserdataBlock], the payload of a USERDATA blob. */
object UserdataCodec {
    private const val HASH_BYTES = 32
    private const val KEY_BYTES = 32

    fun encode(block: UserdataBlock): ByteArray {
        val w = ByteWriter()
        with(block.header) {
            w.string(containerName)
            w.i64(sequenceNumber)
            w.bytes(previousHash.hexToBytes())
        }
        w.i32(block.files.size)
        for (f in block.files) {
            w.string(f.path)
            w.string(f.name)
            w.nullableString(f.note)
            w.string(f.type)
            w.i64(f.createdAt)
            w.i64(f.updatedAt)
            w.blobRef(f.blobRef)
            val preview = f.preview
            if (preview == null) w.u8(0) else {
                w.u8(1)
                w.blobRef(preview.blobRef)
                w.string(preview.type)
            }
        }
        w.i32(block.folders.size)
        block.folders.forEach { w.string(it) }
        w.i32(block.deletes.size)
        for (d in block.deletes) {
            w.blockIndex(d.block)
            w.i64(d.droppedAt)
        }
        w.i32(block.packKeys.size)
        for (k in block.packKeys) {
            w.blockIndex(k.block)
            w.bytes(k.key)
        }
        block.objects.writeTo(w)
        return w.toByteArray()
    }

    fun decode(bytes: ByteArray): UserdataBlock {
        val r = ByteReader(bytes)
        try {
            val header = UserdataHeader(r.string(), r.i64(), r.bytes(HASH_BYTES).toHex())
            val files = List(r.count(1)) {
                UserdataFile(
                    path = r.string(),
                    name = r.string(),
                    note = r.nullableString(),
                    type = r.string(),
                    createdAt = r.i64(),
                    updatedAt = r.i64(),
                    blobRef = r.blobRef(),
                    preview = if (r.flag()) UserdataFilePreview(r.blobRef(), r.string()) else null,
                )
            }
            val folders = List(r.count(4)) { r.string() }
            val deletes = List(r.count(BlockIndex.BYTES + 8)) { PendingDelete(r.blockIndex(), r.i64()) }
            val packKeys = List(r.count(BlockIndex.BYTES + KEY_BYTES)) { PackKey(r.blockIndex(), r.bytes(KEY_BYTES)) }
            val objects = DataBlock.read(r)
            r.expectEnd()
            return UserdataBlock(header, files, folders, deletes, packKeys, objects)
        } catch (e: IllegalArgumentException) {
            throw FormatException("Invalid user_data: ${e.message}")
        }
    }
}
