package com.johnturkson.security

import java.security.MessageDigest

fun String.hash(algorithm: String): ByteArray {
    return MessageDigest.getInstance(algorithm).digest(this.toByteArray())
}
