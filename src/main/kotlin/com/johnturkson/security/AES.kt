package com.johnturkson.security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

fun ByteArray.encryptAESGCM256(key: SecretKey): ByteArray {
    val algorithm = "AES/GCM/NoPadding"
    val initializationVector = generateGCMInitializationVector()
    return this.encrypt(algorithm, key, initializationVector)
}

fun ByteArray.decryptAESGCM256(key: SecretKey): ByteArray {
    val algorithm = "AES/GCM/NoPadding"
    val encryptedData = this.parseEncryptedData()
    val initializationVector = this.parseGCMInitializationVector()
    return encryptedData.decrypt(algorithm, key, initializationVector)
}

fun ByteArray.encrypt(algorithm: String, key: SecretKey, initializationVector: GCMParameterSpec): ByteArray {
    val mode = Cipher.ENCRYPT_MODE
    val encrypted = Cipher.getInstance(algorithm).apply { init(mode, key, initializationVector) }.doFinal(this)
    return initializationVector.iv + encrypted
}

fun ByteArray.decrypt(algorithm: String, key: SecretKey, initializationVector: GCMParameterSpec): ByteArray {
    val mode = Cipher.DECRYPT_MODE
    return Cipher.getInstance(algorithm).apply { init(mode, key, initializationVector) }.doFinal(this)
}

fun ByteArray.parseAESSecretKey(): SecretKey {
    val algorithm = "AES"
    return SecretKeySpec(this, algorithm)
}

fun generateAES256SecretKey(): SecretKey {
    val algorithm = "AES"
    val size = 256
    return generateSecretKey(algorithm, size)
}

fun generateSecretKey(algorithm: String, size: Int, provider: SecureRandom = SecureRandom.getInstanceStrong()): SecretKey {
    return KeyGenerator.getInstance(algorithm).apply { init(size, provider) }.generateKey()
}

private fun generateGCMInitializationVector(): GCMParameterSpec {
    val tagLength = 128
    val nonceSize = 12
    val nonce = generateNonce(nonceSize)
    return GCMParameterSpec(tagLength, nonce)
}

private fun generateNonce(size: Int, provider: SecureRandom = SecureRandom()): ByteArray {
    return ByteArray(size).apply { provider.nextBytes(this) }
}

private fun ByteArray.parseGCMInitializationVector(): GCMParameterSpec {
    val tagLength = 128
    val offset = 0
    val initializationVectorLength = 12
    return GCMParameterSpec(tagLength, this.copyOfRange(offset, initializationVectorLength))
}

private fun ByteArray.parseEncryptedData(): ByteArray {
    val initializationVectorLength = 12
    return this.copyOfRange(initializationVectorLength, this.size)
}
