package squid

import okio.Buffer
import okio.BufferedSink
import okio.BufferedSource
import java.io.Closeable
import java.io.IOException

const val QUIC_PACKET_INITIAL = 0x0
const val QUIC_PACKET_0RTT = 0x01
const val QUIC_PACKET_HANDSHAKE = 0x02
const val QUIC_PACKET_RETRY = 0x03

const val QUIC_PACKET_FLAG_SIZE = UByte.SIZE_BYTES
const val QUIC_PACKET_VERSION_SIZE = UInt.SIZE_BYTES

const val QUIC_PACKET_FLAG_LONG_FORM = 0x80
const val QUIC_PACKET_FLAG_FIXED = 0x40
const val QUIC_PACKET_FLAG_TYPE_MASK = 0x30
const val QUIC_PACKET_FLAG_TYPE_SHIFT = 4
const val QUIC_PACKET_FLAG_PACKET_NUMBER_LENGTH_MASK = 0x03
const val QUIC_PACKET_FLAG_SPIN = 0x20
const val QUIC_PACKET_FLAG_KEY_PHASE = 0x04

interface Packet : Writable {
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

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, handler: Packet.Handler) = PacketReader(source, handler).nextPacket()
    }
}

interface Header : Writable {
    val packetNumberLength: Int

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            if (peek().readByte().toUByte() contains QUIC_PACKET_FLAG_LONG_FORM) {
                LongHeader.read(this)
            } else {
                ShortHeader.read(this)
            }
        }
    }
}

data class LongHeader(
    @JvmField val flags: UByte,
    @JvmField val version: UInt,
    @JvmField val dstConnID: ConnectionID,
    @JvmField val srcConnID: ConnectionID,
) : Header {
    val packetType = ((flags and QUIC_PACKET_FLAG_TYPE_MASK) ushr QUIC_PACKET_FLAG_TYPE_SHIFT).toInt()
    val fixedBit = flags contains QUIC_PACKET_FLAG_FIXED
    val isVersionNegotiation = version == 0U
    override val packetNumberLength = (flags and QUIC_PACKET_FLAG_PACKET_NUMBER_LENGTH_MASK).toInt() + 1

    override val size: Int by lazy {
        QUIC_PACKET_FLAG_SIZE + QUIC_PACKET_VERSION_SIZE + 1 + dstConnID.size + 1 + srcConnID.size
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(flags.toInt())
        writeInt(version.toInt())
        writeConnectionID(dstConnID)
        writeConnectionID(srcConnID)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val flags = readByte().toUByte()
            val version = readInt().toUInt()
            val dstConnID = readConnectionID()
            val srcConnID = readConnectionID()
            LongHeader(flags, version, dstConnID, srcConnID)
        }
    }
}

data class ShortHeader(
    @JvmField val flags: UByte,
    @JvmField val dstConnID: ConnectionID,
) : Header {
    val spin = flags contains QUIC_PACKET_FLAG_SPIN
    val keyPhase = flags contains QUIC_PACKET_FLAG_KEY_PHASE
    override val packetNumberLength = (flags and QUIC_PACKET_FLAG_PACKET_NUMBER_LENGTH_MASK).toInt() + 1

    override val size: Int by lazy {
        QUIC_PACKET_FLAG_SIZE + dstConnID.size
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(flags.toInt())
        writeConnectionID(dstConnID)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val flags = readByte().toUByte()
            val dstConnID = readConnectionID()
            ShortHeader(flags, dstConnID)
        }
    }
}

data class ShortPacket(
    @JvmField val header: ShortHeader,
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet {
    override val size: Int by lazy {
        header.size + header.packetNumberLength + payload.size.toInt()
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        header.writeTo(sink)
        writePacketNumber(packetNumber)
        write(payload, payload.size)
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, header: ShortHeader) = source.run {
            val packetNumber = readPacketNumber(header)
            val payload = Buffer()
            source.readAll(payload)

            ShortPacket(header, packetNumber, payload)
        }
    }
}

data class VersionNegotiationPacket(
    @JvmField val header: LongHeader,
    @JvmField val supportedVersions: UIntArray,
) : Packet {
    override val size: Int by lazy {
        header.size + QUIC_PACKET_VERSION_SIZE * supportedVersions.size
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        header.writeTo(sink)
        supportedVersions.forEach {
            writeInt(it.toInt())
        }
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, header: LongHeader) = source.run {
            val supportedVersions = ArrayList<UInt>()
            do {
                supportedVersions.add(readInt().toUInt())
            } while (!exhausted())
            VersionNegotiationPacket(header, supportedVersions.toUIntArray())
        }
    }
}

data class InitialPacket(
    @JvmField val header: LongHeader,
    @JvmField val token: Token?,
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet {
    override val size: Int by lazy {
        header.size + 1 +
                if (token == null) {
                    0
                } else {
                    VarInt.sizeOf(token.size.toLong()) + token.size
                } +
                VarInt.sizeOf(payload.size) +
                header.packetNumberLength +
                payload.size.toInt()
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        header.writeTo(sink)
        writeToken(token)
        writeVarUInt(payload.size)
        writePacketNumber(packetNumber)
        write(payload, payload.size)
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, header: LongHeader) = source.run {
            val token = readToken()
            val length = readVarUInt()
            val packetNumber = readPacketNumber(header)
            val payload = Buffer()
            readFully(payload, length)

            InitialPacket(header, token, packetNumber, payload)
        }
    }
}

data class ZeroRTTPacket(
    @JvmField val header: LongHeader,
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet {
    override val size: Int by lazy {
        header.size + VarInt.sizeOf(payload.size) + header.packetNumberLength + payload.size.toInt()
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        header.writeTo(sink)
        writeVarUInt(payload.size)
        writePacketNumber(packetNumber)
        write(payload, payload.size)
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, header: LongHeader) = source.run {
            val length = readVarUInt()
            val packetNumber = readPacketNumber(header)
            val payload = Buffer()
            readFully(payload, length)

            ZeroRTTPacket(header, packetNumber, payload)
        }
    }
}

data class HandshakePacket(
    @JvmField val header: LongHeader,
    @JvmField val packetNumber: PacketNumber,
    @JvmField val payload: Buffer,
) : Packet {
    override val size: Int by lazy {
        header.size + VarInt.sizeOf(payload.size) + header.packetNumberLength + payload.size.toInt()
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        header.writeTo(sink)
        writeVarUInt(payload.size)
        writePacketNumber(packetNumber)
        write(payload, payload.size)
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, header: LongHeader) = source.run {
            val length = readVarUInt()
            val packetNumber = readPacketNumber(header)
            val payload = Buffer()
            readFully(payload, length)

            HandshakePacket(header, packetNumber, payload)
        }
    }
}

data class RetryPacket(
    @JvmField val header: LongHeader,
    @JvmField val token: Token,
) : Packet {
    override val size = header.size + token.size

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        header.writeTo(sink)
        write(token)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource, header: LongHeader) = source.run {
            RetryPacket(header, readByteArray())
        }
    }
}

class PacketReader(
    private val source: BufferedSource,
    private val handler: Packet.Handler,
) : Closeable {
    @Throws(IOException::class)
    override fun close() = source.close()

    @Throws(IOException::class)
    fun nextPacket() {
        when (val header = Header.read(source)) {
            is LongHeader -> header.run {
                if (isVersionNegotiation) {
                    VersionNegotiationPacket.read(source, header).run {
                        handler.versionNegotiation(dstConnID, srcConnID, supportedVersions)
                    }
                } else {
                    when (packetType) {
                        QUIC_PACKET_INITIAL -> InitialPacket.read(source, header).run {
                            handler.initial(dstConnID, srcConnID, token, packetNumber, payload)
                        }
                        QUIC_PACKET_0RTT -> ZeroRTTPacket.read(source, header).run {
                            handler.zeroRTT(dstConnID, srcConnID, packetNumber, payload)
                        }
                        QUIC_PACKET_HANDSHAKE -> HandshakePacket.read(source, header).run {
                            handler.handshake(dstConnID, srcConnID, packetNumber, payload)
                        }
                        QUIC_PACKET_RETRY -> RetryPacket.read(source, header).run {
                            handler.retry(dstConnID, srcConnID, token)
                        }
                    }
                }
            }
            is ShortHeader -> header.run {
                ShortPacket.read(source, header).run {
                    handler.short(dstConnID, packetNumber, payload)
                }
            }
        }
    }
}

@Throws(IOException::class)
fun BufferedSource.readConnectionID() = ConnectionID(readByteArray(readByte().toUByte().toLong()))

@Throws(IOException::class)
fun BufferedSink.writeConnectionID(connectionID: ConnectionID) = writeByte(connectionID.size).write(connectionID.id)

@Throws(IOException::class, IllegalArgumentException::class)
fun BufferedSource.readPacketNumber(header: Header): PacketNumber =
    (1..header.packetNumberLength).fold(0L, { acc, _ -> acc + readByte().toUByte().toLong() })

@Throws(IOException::class)
fun BufferedSink.writePacketNumber(pn: PacketNumber) = when {
    pn < Byte.MAX_VALUE.toLong() -> writeByte(pn.toInt())
    pn < Short.MAX_VALUE.toLong() -> writeShort(pn.toInt())
    else -> writeInt(pn.toInt())
}

@Throws(IOException::class, IllegalArgumentException::class)
fun BufferedSource.readToken() = when (val len = readVarUInt()) {
    0L -> null
    else -> readByteArray(len)
}

@Throws(IOException::class)
fun BufferedSink.writeToken(token: Token?) = if (token == null) {
    writeByte(0)
} else {
    writeVarUInt(token.size.toLong()).write(token)
}
