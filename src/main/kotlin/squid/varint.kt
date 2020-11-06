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

const val VAR_INT_2BYTE_PREFIX = 0x4000UL
const val VAR_INT_4BYTE_PREFIX = 0x8000_0000UL
const val VAR_INT_8BYTE_PREFIX = 0xc000_0000_0000_0000UL

const val VAR_INT_1BYTE_MAX = 0x40UL
const val VAR_INT_2BYTE_MAX = 0x4000UL
const val VAR_INT_4BYTE_MAX = 0x4000_0000UL
const val VAR_INT_8BYTE_MAX = 0x4000_0000_0000_0000UL

@Throws(IOException::class)
fun BufferedSource.readVarUInt() = VarInt.read(this).toLong()

@Throws(IOException::class)
fun BufferedSink.writeVarUInt(vararg args: Long): BufferedSink {
    args.forEach { VarInt(it.toULong()).write(this) }
    return this
}

inline class VarInt(val n: ULong) {
    fun toLong() = n.toLong()
    fun toULong() = n

    @Throws(IOException::class, IllegalArgumentException::class)
    fun write(s: BufferedSink): BufferedSink {
        when {
            n < VAR_INT_1BYTE_MAX -> s.writeByte(n.toInt())
            n < VAR_INT_2BYTE_MAX -> s.writeShort((n or VAR_INT_2BYTE_PREFIX).toInt())
            n < VAR_INT_4BYTE_MAX -> s.writeInt((n or VAR_INT_4BYTE_PREFIX).toInt())
            n < VAR_INT_8BYTE_MAX -> s.writeLong((n or VAR_INT_8BYTE_PREFIX).toLong())
            else -> throw IllegalArgumentException("out of range")
        }
        return s
    }

    companion object {
        @Throws(IllegalArgumentException::class)
        fun sizeOf(n: Long) = n.toULong().let {
            when {
                it < VAR_INT_1BYTE_MAX -> UByte.SIZE_BYTES
                it < VAR_INT_2BYTE_MAX -> UShort.SIZE_BYTES
                it < VAR_INT_4BYTE_MAX -> UInt.SIZE_BYTES
                it < VAR_INT_8BYTE_MAX -> ULong.SIZE_BYTES
                else -> throw IllegalArgumentException("out of range")
            }
        }

        @Throws(IOException::class)
        fun read(s: BufferedSource): VarInt {
            val b = s.readByte().toUByte()
            val len = when ((b and VAR_INT_MASK).toInt()) {
                VAR_INT_1BYTE -> UByte.SIZE_BYTES
                VAR_INT_2BYTE -> UShort.SIZE_BYTES
                VAR_INT_4BYTE -> UInt.SIZE_BYTES
                VAR_INT_8BYTE -> ULong.SIZE_BYTES
                else -> 0
            }
            val n = (2..len).fold((b and VAR_INT_VALUE).toULong(), { acc, _ ->
                (acc shl UByte.SIZE_BITS) or s.readByte().toUByte().toULong()
            })

            return VarInt(n)
        }
    }
}
