package squid

import okio.Buffer
import okio.BufferedSource
import java.io.Closeable
import java.io.IOException

const val QUIC_PACKET_INITIAL = 0x0
const val QUIC_PACKET_0RTT = 0x01
const val QUIC_PACKET_HANDSHAKE = 0x02
const val QUIC_PACKET_RETRY = 0x03

const val QUIC_PACKET_FLAG_LONG_FORM = 0x80
const val QUIC_PACKET_FLAG_FIXED = 0x40
const val QUIC_PACKET_FLAG_TYPE_MASK = 0x30
const val QUIC_PACKET_FLAG_TYPE_SHIFT = 4
const val QUIC_PACKET_FLAG_PACKET_NUMBER_LENGTH_MASK = 0x03
const val QUIC_PACKET_FLAG_SPIN = 0x20
const val QUIC_PACKET_FLAG_KEY_PHASE = 0x04

interface Packet {
    interface Handler {
        fun versionNegotiation(dstConnID: ConnectionID, srcConnID: ConnectionID, supportedVersions: UIntArray)

        fun initial(
            dstConnID: ConnectionID,
            srcConnID: ConnectionID,
            token: Token?,
            packetNumber: PacketNumber,
            payload: Buffer
        )

        fun zeroRTT(dstConnID: ConnectionID, srcConnID: ConnectionID, packetNumber: PacketNumber, payload: Buffer)

        fun handshake(dstConnID: ConnectionID, srcConnID: ConnectionID, packetNumber: PacketNumber, payload: Buffer)

        fun retry(dstConnID: ConnectionID, srcConnID: ConnectionID, token: Token)

        fun short(dstConnID: ConnectionID, packetNumber: PacketNumber, payload: Buffer)
    }
}

private fun isLongHeader(source: BufferedSource) =
    source.peek().readByte().toUByte() contains QUIC_PACKET_FLAG_LONG_FORM

interface Header {
    val packetNumberLength: Int
}

data class LongHeader(
    @JvmField val flags: UByte,
    @JvmField val version: UInt,
    @JvmField val dstConnID: ConnectionID,
    @JvmField val srcConnID: ConnectionID,
) : Header {
    fun getType() = ((flags and QUIC_PACKET_FLAG_TYPE_MASK) ushr QUIC_PACKET_FLAG_TYPE_SHIFT).toInt()
    fun isVersionNegotiation(): Boolean = version == 0U
    override val packetNumberLength = (flags and QUIC_PACKET_FLAG_PACKET_NUMBER_LENGTH_MASK).toInt() + 1
}

data class ShortHeader(
    @JvmField val flags: UByte,
    @JvmField val dstConnID: ConnectionID,
) : Header {
    fun isSpin() = flags contains QUIC_PACKET_FLAG_SPIN
    fun isKeyPhase() = flags contains QUIC_PACKET_FLAG_KEY_PHASE
    override val packetNumberLength = (flags and QUIC_PACKET_FLAG_PACKET_NUMBER_LENGTH_MASK).toInt() + 1
}

data class ShortPacket(
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet

data class VersionNegotiationPacket(
    @JvmField val supportedVersion: UIntArray,
) : Packet

data class InitialPacket(
    @JvmField val token: Token?,
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet

data class ZeroRTTPacket(
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet

data class HandshakePacket(
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet

data class RetryPacket(
    @JvmField val token: Token,
) : Packet

class PacketReader(
    private val source: BufferedSource,
    private val handler: Packet.Handler,
) : Closeable {
    @Throws(IOException::class)
    override fun close() = source.close()

    @Throws(IOException::class)
    fun nextPacket() {
        source.run {
            if (isLongHeader(source)) {
                readLongHeader().let {
                    if (it.isVersionNegotiation()) {
                        val (supportedVersions) = readVersionNegotiationPacket()
                        handler.versionNegotiation(it.dstConnID, it.srcConnID, supportedVersions)
                    } else {
                        when (it.getType()) {
                            QUIC_PACKET_INITIAL -> {
                                val (token, packetNumber, payload) = readInitialPacket(it)
                                handler.initial(it.dstConnID, it.srcConnID, token, packetNumber, payload)
                            }
                            QUIC_PACKET_0RTT -> {
                                val (packetNumber, payload) = readZeroRTTPacket(it)
                                handler.zeroRTT(it.dstConnID, it.srcConnID, packetNumber, payload)
                            }
                            QUIC_PACKET_HANDSHAKE -> {
                                val (packetNumber, payload) = readHandshakePacket(it)
                                handler.handshake(it.dstConnID, it.srcConnID, packetNumber, payload)
                            }
                            QUIC_PACKET_RETRY -> {
                                val (token) = readRetryPacket()
                                handler.retry(it.dstConnID, it.srcConnID, token)
                            }
                        }
                    }
                }
            } else {
                readShortHeader().let {
                    val packetNumber = readPacketNumber(it)
                    val payload = Buffer()
                    source.readAll(payload)

                    handler.short(it.dstConnID, packetNumber, payload)
                }
            }
        }
    }
}

@Throws(IOException::class)
fun BufferedSource.readConnectionID(): ConnectionID {
    val len = readByte().toUByte().toLong()
    return readByteArray(len)
}

@Throws(IOException::class)
fun BufferedSource.readLongHeader(): LongHeader {
    val flags = readByte().toUByte()
    val version = readInt().toUInt()
    val dstConnID = readConnectionID()
    val srcConnID = readConnectionID()
    return LongHeader(flags, version, dstConnID, srcConnID)
}

@Throws(IOException::class)
fun BufferedSource.readShortHeader(): ShortHeader {
    val flags = readByte().toUByte()
    val dstConnID = readConnectionID()
    return ShortHeader(flags, dstConnID)
}

@Throws(IOException::class, IllegalArgumentException::class)
fun BufferedSource.readPacketNumber(header: Header): PacketNumber = when (header.packetNumberLength) {
    1 -> readByte().toUByte().toLong()
    2 -> readShort().toUShort().toLong()
    3 -> ((readByte().toUByte().toUInt() shl 16) + readShort().toUShort()).toLong()
    4 -> readInt().toUInt().toLong()
    else -> throw IllegalArgumentException("packet number length")
}

@Throws(IOException::class)
fun BufferedSource.readVersionNegotiationPacket(): VersionNegotiationPacket {
    val supportedVersions = ArrayList<UInt>()
    do {
        supportedVersions.add(readInt().toUInt())
    } while (!exhausted())
    return VersionNegotiationPacket(supportedVersions.toUIntArray())
}

@Throws(IOException::class)
fun BufferedSource.readInitialPacket(header: LongHeader): InitialPacket {
    val tokenLen = readVarUInt().toLong()
    val token = if (tokenLen == 0L) {
        null
    } else {
        readByteArray(tokenLen)
    }
    val length = readVarUInt()
    val packetNumber = readPacketNumber(header)
    val payload = Buffer()
    readFully(payload, length)

    return InitialPacket(token, packetNumber, payload)
}

@Throws(IOException::class)
fun BufferedSource.readZeroRTTPacket(header: LongHeader): ZeroRTTPacket {
    val length = readVarUInt()
    val packetNumber = readPacketNumber(header)
    val payload = Buffer()
    readFully(payload, length)

    return ZeroRTTPacket(packetNumber, payload)
}

@Throws(IOException::class)
fun BufferedSource.readHandshakePacket(header: LongHeader): HandshakePacket {
    val length = readVarUInt()
    val packetNumber = readPacketNumber(header)
    val payload = Buffer()
    readFully(payload, length)

    return HandshakePacket(packetNumber, payload)
}

@Throws(IOException::class)
fun BufferedSource.readRetryPacket() = RetryPacket(readByteArray())
