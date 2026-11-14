package com.opaquer_app.opaquerlib.crypto

import com.opaquer_app.opaquerlib.core.BlockIndex
import com.opaquer_app.opaquerlib.core.toBytes

const val KEY_BYTES = 32

/**
 * Everything derived from the root key: the user_data addresses and the user_data blob keys.
 * Pack keys are random and live in the user_data block, so they do not depend on the root key.
 * Each secret comes from HKDF with its own label, and no value keys two different primitives.
 */
class KeySchedule(rootKey: ByteArray) {
    init {
        require(rootKey.size == KEY_BYTES) { "Root key must be $KEY_BYTES bytes" }
    }

    private val commitKey = Hkdf.expand(rootKey, label("opaque/v1/commit"), KEY_BYTES)
    private val userdataKey = Hkdf.expand(rootKey, label("opaque/v1/userdata-key"), KEY_BYTES)

    /** Address of user_data version [seq]. */
    fun userdataId(seq: Long): BlockIndex {
        require(seq >= 0) { "Negative sequence number" }
        return BlockIndex.fromBytes(hmacSha256(commitKey, label("opaque/v1/userdata"), seq.toBytes()))
    }

    /** Key of the user_data blob stored at [id]. */
    fun userdataBlobKey(id: BlockIndex): ByteArray = Hkdf.expand(userdataKey, id.toBytes(), KEY_BYTES)

    companion object {
        /**
         * root key = HKDF(ikm = Argon2id(password, salt), salt = cold key, info = "root"),
         * with the Argon2id salt itself derived from the cold key, so nothing is fetched before login.
         * Neither secret alone gives the root key.
         */
        fun deriveRootKey(coldKey: ByteArray, password: CharArray, kdf: PasswordKdf): ByteArray {
            require(coldKey.size == KEY_BYTES) { "Cold key must be $KEY_BYTES bytes" }
            val salt = Hkdf.expand(coldKey, label("opaque/v1/password-salt"), 16)
            val stretched = kdf.derive(password, salt, KEY_BYTES)
            return Hkdf.derive(stretched, coldKey, label("opaque/v1/root"), KEY_BYTES).also { stretched.fill(0) }
        }
    }
}
