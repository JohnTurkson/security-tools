package com.johnturkson.tools.security

fun ByteArray.toHexString(): String {
    val radix = 0x10
    val shift = 0x4
    val mask = 0xf
    val separator = ""
    
    return this.map { byte -> byte.toInt() }
        .map { bits -> (bits shr shift and mask) to (bits and mask) }
        .joinToString(separator) { (high, low) -> high.toString(radix) + low.toString(radix) }
}

fun String.toHexBytes(): ByteArray {
    val radix = 0x10
    val padding = '0'
    
    val length = this.length - this.length / 2 + (this.length + 1) / 2
    val data = this.padStart(length, padding)
    
    return data.indices.asSequence()
        .filter { index -> index % 2 == 0 }
        .map { index -> data[index] to data[index + 1] }
        .map { (high, low) -> high.toString() + low.toString() }
        .map { value -> value.toInt(radix) }
        .map { value -> value.toByte() }
        .toList()
        .toByteArray()
}
