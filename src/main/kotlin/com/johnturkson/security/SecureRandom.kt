package com.johnturkson.security

import java.security.SecureRandom

fun generateSecureRandomBytes(size: Int): ByteArray {
    return ByteArray(size).apply { SecureRandom.getInstanceStrong().nextBytes(this) }
}
