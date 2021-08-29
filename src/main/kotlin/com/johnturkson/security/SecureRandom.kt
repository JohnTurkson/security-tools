package com.johnturkson.security

import java.security.SecureRandom

fun generateSecureRandomBytes(size: Int, provider: SecureRandom = SecureRandom.getInstanceStrong()): ByteArray {
    return ByteArray(size).apply { provider.nextBytes(this) }
}
