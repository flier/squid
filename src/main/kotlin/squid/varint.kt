package squid

import okio.BufferedSink
import okio.BufferedSource
import java.io.IOException

const val VAR_INT_MASK = 0xc0
const val VAR_INT_VALUE = 0x3f
const val VAR_INT_1BYTE = 0x00
const val VAR_INT_2BYTE = 0x40
const val VAR_INT_4BYTE = 0x80
const val VAR_INT_8BYTE = 0xc0

data class VarInt(val n: ULong) {
    override operator fun equals(other: Any?) = when (other) {
        is VarInt -> n == other.n
        is ULong -> n == other
        is Long -> n == other
        is UInt -> n == other
        is Int -> n == other
        is UShort -> n == other
        is Short -> n == other
        is UByte -> n == other
        is Byte -> n == other
        else -> false
    }

    override fun hashCode()= n.hashCode()

    fun toULong() = n

    @Throws(IOException::class, IllegalArgumentException::class)
    fun write(s: BufferedSink): BufferedSink {
        when {
            n <= 0x3fUL -> s.writeByte(n.toInt())
            n <= 0x3fffUL -> s.writeShort((VAR_INT_2BYTE shl 8) or n.toInt())
            n <= 0x3fffffffUL -> s.writeInt((VAR_INT_4BYTE shl 24) or n.toInt())
            n <= 0x3fffffffffffffffUL -> s.writeLong(((VAR_INT_8BYTE.toULong() shl 56) or n).toLong())
            else -> throw IllegalArgumentException("out of range")
        }
        return s
    }

    companion object {
        @Throws(IOException::class)
        fun read(s: BufferedSource): VarInt {
            val b = s.readByte().toUByte()
            val len = when ((b and VAR_INT_MASK).toInt()) {
                VAR_INT_1BYTE -> 1
                VAR_INT_2BYTE -> 2
                VAR_INT_4BYTE -> 4
                VAR_INT_8BYTE -> 8
                else -> 0
            }
            var value = (b and VAR_INT_VALUE).toULong()
            for (i in 2..len) {
                value = (value shl 8) or s.readByte().toUByte().toULong()
            }
            return VarInt(value)
        }
    }
}

