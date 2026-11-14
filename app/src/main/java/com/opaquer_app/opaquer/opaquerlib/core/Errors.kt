package com.opaquer_app.opaquerlib.core

/** Base class for every failure the library reports on purpose. */
open class OpaqueException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** A blob failed authentication. Corruption and tampering cannot be told apart, so they share this error. */
class IntegrityException(message: String = "Blob failed authentication", cause: Throwable? = null) :
    OpaqueException(message, cause)

/** Authenticated data that does not follow the format: a bug or an incompatible client. */
class FormatException(message: String) : OpaqueException(message)

/** A blob that should exist is not on the storage. [id] is null when no specific blob is meant. */
class MissingBlobException(val id: BlockIndex?, message: String) : OpaqueException(message)

/** The storage served an older or different state than this device has already seen. */
class RollbackException(message: String) : OpaqueException(message)

/** Another writer created the same address first. */
class ConflictException(message: String) : OpaqueException(message)

/**
 * No user_data version exists at the addresses this root key gives: a wrong password or cold key,
 * a root key from before a password change, or a storage that lost every version.
 * Without a stored password verifier these cannot be told apart.
 */
class ArchiveNotFoundException : OpaqueException("No archive found for this cold key and password")

/** The data does not fit into one block. */
class CapacityException(message: String) : OpaqueException(message)
