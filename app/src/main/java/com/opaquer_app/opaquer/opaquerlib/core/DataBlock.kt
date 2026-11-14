package com.opaquer_app.opaquerlib.core

/** Position of one object inside [DataBlock.data]. */
data class DataBlockEntry(val offset: Int, val length: Int)

/**
 * Objects packed together. The object id is the index into [entries].
 *
 * Used for pack blobs (type DATA) and for the objects carried inside a user_data block.
 * Encoding: count (4B) || count × (offset 4B, length 4B) || data length (4B) || data
 */
class DataBlock(val entries: List<DataBlockEntry>, val data: ByteArray) {
    init {
        for (e in entries) {
            require(e.offset >= 0 && e.length >= 0 && e.offset.toLong() + e.length <= data.size) {
                "Object outside the data area"
            }
        }
    }

    val size: Int get() = entries.size

    operator fun get(objectId: Int): ByteArray {
        val e = entries.getOrNull(objectId) ?: throw FormatException("Object $objectId out of range")
        return data.copyOfRange(e.offset, e.offset + e.length)
    }

    fun encode(): ByteArray = ByteWriter().also { writeTo(it) }.toByteArray()

    internal fun writeTo(w: ByteWriter) {
        w.i32(entries.size)
        for (e in entries) {
            w.i32(e.offset)
            w.i32(e.length)
        }
        w.i32(data.size)
        w.bytes(data)
    }

    override fun equals(other: Any?): Boolean =
        other is DataBlock && entries == other.entries && data.contentEquals(other.data)

    override fun hashCode(): Int = 31 * entries.hashCode() + data.contentHashCode()

    companion object {
        const val HEADER_BYTES = 8
        const val ENTRY_BYTES = 8

        val EMPTY = DataBlock(emptyList(), ByteArray(0))

        fun encodedSize(count: Int, dataBytes: Long): Long = HEADER_BYTES + ENTRY_BYTES.toLong() * count + dataBytes

        fun decode(bytes: ByteArray): DataBlock {
            val r = ByteReader(bytes)
            return read(r).also { r.expectEnd() }
        }

        internal fun read(r: ByteReader): DataBlock {
            val count = r.count(ENTRY_BYTES)
            val entries = List(count) { DataBlockEntry(r.i32(), r.i32()) }
            val data = r.bytes(r.i32())
            for (e in entries) {
                if (e.offset < 0 || e.length < 0 || e.offset.toLong() + e.length > data.size) {
                    throw FormatException("Object outside the data area")
                }
            }
            return DataBlock(entries, data)
        }
    }
}

/** Fills a [DataBlock] up to [capacity] encoded bytes. */
class DataBlockBuilder(private val capacity: Long) {
    private val objects = ArrayList<ByteArray>()
    private var dataBytes = 0L

    val isEmpty: Boolean get() = objects.isEmpty()

    fun fits(length: Int): Boolean = DataBlock.encodedSize(objects.size + 1, dataBytes + length) <= capacity

    /** Adds a copy of [bytes] and returns its object id. */
    fun add(bytes: ByteArray): Int {
        if (!fits(bytes.size)) throw CapacityException("Object of ${bytes.size} bytes does not fit")
        objects += bytes.copyOf()
        dataBytes += bytes.size
        return objects.size - 1
    }

    operator fun get(objectId: Int): ByteArray = objects[objectId].copyOf()

    fun build(): DataBlock {
        val data = ByteArray(dataBytes.toInt())
        var offset = 0
        val entries = objects.map { obj ->
            obj.copyInto(data, offset)
            DataBlockEntry(offset, obj.size).also { offset += obj.size }
        }
        return DataBlock(entries, data)
    }
}
