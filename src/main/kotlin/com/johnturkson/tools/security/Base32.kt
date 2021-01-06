package com.johnturkson.tools.security

fun ByteArray.encodeBase32(): String {
    val radix = 0x2
    val mask = 0xff
    val byteLength = 0x8
    val baseLength = 0x5
    
    val byteExtension = '0'
    val baseExtension = '0'
    val byteSeparator = ""
    val baseSeparator = ""
    val basePadding = '='
    
    val characterRange = 0..25
    val characterOffset = 65
    val digitOffset = 24
    
    val encoded = this.toList()
        .map { byte -> byte.toInt() and mask }
        .joinToString(byteSeparator) { byte -> byte.toString(radix).padStart(byteLength, byteExtension) }
        .chunked(baseLength)
        .asSequence()
        .map { bits -> bits.padEnd(baseLength, baseExtension) }
        .map { bits -> bits.toInt(radix) }
        .map { base -> if (base in characterRange) base + characterOffset else base + digitOffset }
        .map { base -> base.toChar() }
        .joinToString(baseSeparator)
    
    val lengthMultiple = 8
    val paddedLength = when {
        encoded.length % lengthMultiple != 0 -> encoded.length - (encoded.length % lengthMultiple) + lengthMultiple
        else -> encoded.length
    }
    
    return encoded.padEnd(paddedLength, basePadding)
}

fun String.decodeBase32(): ByteArray {
    val radix = 0x2
    val byteLength = 0x8
    val baseLength = 0x5
    
    val baseExtension = '0'
    val baseSeparator = ""
    val basePadding = '='
    
    val letterOffset = 65
    val digitOffset = 24
    
    return this.toUpperCase()
        .dropLastWhile { base -> base == basePadding }
        .map { base -> if (base.isLetter()) base - letterOffset else base - digitOffset }
        .map { base -> base.toInt() }
        .map { base -> base.toString(radix) }
        .joinToString(baseSeparator) { base -> base.padStart(baseLength, baseExtension) }
        .chunked(byteLength)
        .dropLastWhile { bits -> bits.length != byteLength }
        .map { bits -> bits.toInt(radix) }
        .map { bits -> bits.toByte() }
        .toByteArray()
}
