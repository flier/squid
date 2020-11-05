package squid

import okio.Buffer
import okio.BufferedSource

enum class Type(val b: Int) {
    Initial(TYPE_INITIAL),
    ZeroRTT(TYPE_0RTT),
    Handshake(TYPE_HANDSHAKE),
    Retry(TYPE_RETRY);

    companion object {
        fun from(b: UByte) = values().first { it.b == b.toInt() }
    }
}

fun isLongHeader(source: BufferedSource) = source.peek().readByte().toUByte() contains FLAG_LONG_FORM

data class LongHeader(
    @JvmField val flags: UByte,
    @JvmField val version: UInt,
    @JvmField val dstConnID: ConnectionID,
    @JvmField val srcConnID: ConnectionID,
) {
    fun getType() = Type.from((flags and FLAG_TYPE_MASK) ushr FLAG_TYPE_SHIFT)
    fun getPacketNumberLength() = (flags and FLAG_PACKET_NUMBER_LENGTH_MASK).toLong() + 1
    fun isVersionNegotiation(): Boolean = version == 0U
}

data class ShortHeader(
    @JvmField val flags: UByte,
    @JvmField val dstConnID: ConnectionID,
) {
    fun isSpin() = flags contains FLAG_SPIN
    fun isKeyPhase() = flags contains FLAG_KEY_PHASE
    fun getPacketNumberLength() = (flags and FLAG_PACKET_NUMBER_LENGTH_MASK).toLong() + 1
}

data class ShortPacket(
    @JvmField val packetNumber: UByteArray,
    @JvmField val payload: Buffer,
) {

}

data class VersionNegotiationPacket(
    @JvmField val supportedVersion: UIntArray,
) {

}

data class InitialPacket(
    @JvmField val token: UByteArray?,
    @JvmField val packetNumber: UByteArray,
    @JvmField val payload: Buffer,
) {}

data class ZeroRTTPacket(
    @JvmField val packetNumber: UByteArray,
    @JvmField val payload: Buffer,
) {}

data class HandshakePacket(
    @JvmField val packetNumber: UByteArray,
    @JvmField val payload: Buffer,
) {
}

data class RetryPacket(
    @JvmField val token: UByteArray,
)
