package squid

import okio.Buffer
import okio.BufferedSink
import okio.BufferedSource
import java.io.IOException

infix fun Byte.and(mask: Int): UByte = (toInt() and mask).toUByte()
infix fun UByte.and(mask: Int): UByte = (toInt() and mask).toUByte()
infix fun Short.and(mask: Int): UShort = (toInt() and mask).toUShort()
infix fun Int.and(mask: Long): UInt = (toLong() and mask).toUInt()

infix fun UByte.contains(flags: Int): Boolean = (toInt() and flags) == flags
infix fun UByte.ushr(bitCount: Int): UByte = (toInt() shr bitCount).toUByte()

fun UByteArray.source(): BufferedSource {
    val buf = Buffer()
    buf.write(toByteArray())
    return buf
}

interface Writable {
    val size: Int

    @Throws(IOException::class)
    fun writeTo(sink: BufferedSink): BufferedSink
}
