package squid

import okio.Buffer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

val TEST_ENCODE_DATA = arrayOf(
    Pair(ubyteArrayOf(0x25U), 37UL),
    Pair(ubyteArrayOf(0x7bU, 0xbdU), 15293UL),
    Pair(ubyteArrayOf(0x9dU, 0x7fU, 0x3eU, 0x7dU), 494878333UL),
    Pair(ubyteArrayOf(0xc2U, 0x19U, 0x7cU, 0x5eU, 0xffU, 0x14U, 0xe8U, 0x8cU), 151288809941952652UL),
)

val TEST_DECODE_DATA = TEST_ENCODE_DATA + Pair(ubyteArrayOf(0x40U, 0x25U), 37UL)

fun UByteArray.toHexString() = toByteArray().joinToString(", ", "[", "]") { "0x%02x".format(it) }

class VarIntTest {
    @Test
    fun `decode variable-length integer`() {
        for ((b, n) in TEST_DECODE_DATA) {
            assertEquals(n, VarInt.read(b.source()).toULong(), "decode $n from ${b.toHexString()}")
        }
    }

    @Test
    fun `encode variable-length integer`() {
        for ((b, n) in TEST_ENCODE_DATA) {
            assertArrayEquals(
                b.toTypedArray(),
                (VarInt(n).write(Buffer()) as Buffer).readByteArray().toUByteArray().toTypedArray(),
                "encode $n to ${b.toHexString()}"
            )
        }
    }
}