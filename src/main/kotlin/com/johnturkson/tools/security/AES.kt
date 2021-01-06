package com.johnturkson.tools.security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

fun generateNonce(size: Int, provider: SecureRandom = SecureRandom()): ByteArray {
    return ByteArray(size).apply { provider.nextBytes(this) }
}

fun generateGCMInitializationVector(): GCMParameterSpec {
    val tagLength = 128
    val nonceSize = 12
    val nonce = generateNonce(nonceSize)
    return GCMParameterSpec(tagLength, nonce)
}

fun ByteArray.parseGCMInitializationVector(): GCMParameterSpec {
    val tagLength = 128
    val offset = 0
    val initializationVectorLength = 12
    return GCMParameterSpec(tagLength, this.copyOfRange(offset, initializationVectorLength))
}

fun ByteArray.parseEncryptedData(): ByteArray {
    val initializationVectorLength = 12
    return this.copyOfRange(initializationVectorLength, this.size)
}

fun generateKey(algorithm: String, size: Int, provider: SecureRandom = SecureRandom.getInstanceStrong()): SecretKey {
    return KeyGenerator.getInstance(algorithm).apply { init(size, provider) }.generateKey()
}

fun generateAES256Key(): SecretKey {
    val algorithm = "AES"
    val size = 256
    return generateKey(algorithm, size)
}

fun ByteArray.encrypt(algorithm: String, key: SecretKey, initializationVector: GCMParameterSpec): ByteArray {
    val mode = Cipher.ENCRYPT_MODE
    val encrypted = Cipher.getInstance(algorithm).apply { init(mode, key, initializationVector) }.doFinal(this)
    return initializationVector.iv + encrypted
}

fun ByteArray.encryptAESGCM256(key: SecretKey, initializationVector: GCMParameterSpec): ByteArray {
    val algorithm = "AES/GCM/NoPadding"
    return this.encrypt(algorithm, key, initializationVector)
}

fun ByteArray.decrypt(algorithm: String, key: SecretKey, initializationVector: GCMParameterSpec): ByteArray {
    val mode = Cipher.DECRYPT_MODE
    return Cipher.getInstance(algorithm).apply { init(mode, key, initializationVector) }.doFinal(this)
}

fun ByteArray.decryptAESGCM256(key: SecretKey): ByteArray {
    val algorithm = "AES/GCM/NoPadding"
    val encryptedData = this.parseEncryptedData()
    val initializationVector = this.parseGCMInitializationVector()
    return encryptedData.decrypt(algorithm, key, initializationVector)
}

fun main() {
    val data = "Hello World".toByteArray()
    val key = generateAES256Key()
    val initializationVector = generateGCMInitializationVector()
    val encrypted = data.encryptAESGCM256(key, initializationVector)
    encrypted.toString()
    
    println()
    
    val decrypted = encrypted.decryptAESGCM256(key)
    decrypted.forEach { print(it) }
}
