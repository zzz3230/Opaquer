package com.opaquer_app.opaquerlib.crypto

import com.opaquer_app.opaquerlib.core.IntegrityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

interface Aead {
    val keySize: Int
    val nonceSize: Int
    val tagSize: Int

    /** Returns the ciphertext followed by the tag. */
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray

    /** Throws [IntegrityException] when the tag does not verify. */
    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray
}

/** Password stretching. The app should supply Argon2id, for example from libsodium. */
fun interface PasswordKdf {
    fun derive(password: CharArray, salt: ByteArray, length: Int): ByteArray
}

/** Everything platform-specific the library needs for cryptography. */
class CryptoSuite(
    val aead: Aead,
    val passwordKdf: PasswordKdf,
    val random: SecureRandom = SecureRandom(),
)

/**
 * ChaCha20-Poly1305 with a 12-byte nonce from the platform provider:
 * SunJCE on the JVM (Java 11+), Conscrypt on Android (API 28+).
 * Every blob has its own key, so random 12-byte nonces are safe here.
 */
class JdkChaCha20Poly1305 : Aead {
    override val keySize = 32
    override val nonceSize = 12
    override val tagSize = 16

    private val transformation: String by lazy {
        TRANSFORMATIONS.firstOrNull { runCatching { Cipher.getInstance(it) }.isSuccess }
            ?: throw UnsupportedOperationException("ChaCha20-Poly1305 is not available on this platform")
    }

    override fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray =
        cipher(Cipher.ENCRYPT_MODE, key, nonce, ad).doFinal(plaintext)

    override fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray =
        try {
            cipher(Cipher.DECRYPT_MODE, key, nonce, ad).doFinal(ciphertext)
        } catch (e: AEADBadTagException) {
            throw IntegrityException(cause = e)
        }

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, ad: ByteArray): Cipher {
        require(key.size == keySize && nonce.size == nonceSize) { "Wrong key or nonce size" }
        return Cipher.getInstance(transformation).apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(ad)
        }
    }

    companion object {
        // JVM name first, Android name second
        private val TRANSFORMATIONS = listOf("ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding")
    }
}
