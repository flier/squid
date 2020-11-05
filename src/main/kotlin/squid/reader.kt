package squid

import okio.Buffer
import java.io.Closeable
import java.io.IOException
import okio.BufferedSource

interface PacketHandler {
    fun versionNegotiationPacket(dstConnID: ConnectionID, srcConnID: ConnectionID, supportedVersions: UIntArray)

    fun initialPacket(dstConnID: ConnectionID, srcConnID: ConnectionID, token: UByteArray?, packetNumber: UByteArray, payload: Buffer)

    fun zeroRTTPacket(dstConnID: ConnectionID, srcConnID: ConnectionID, packetNumber: UByteArray, payload: Buffer)

    fun handshakePacket(dstConnID: ConnectionID, srcConnID: ConnectionID, packetNumber: UByteArray, payload: Buffer)

    fun retryPacket(dstConnID: ConnectionID, srcConnID: ConnectionID, token: UByteArray)

    fun shortPacket(dstConnID: ConnectionID, packetNumber: UByteArray, payload: Buffer)
}

@ExperimentalUnsignedTypes
class PacketReader(
    private val source: BufferedSource,
    private val handler: PacketHandler,
) : Closeable {
    @Throws(IOException::class)
    override fun close() = source.close()

    @Throws(IOException::class)
    fun nextPacket() {
        if (isLongHeader(source)) {
            readLongHeader().let {
                if (it.isVersionNegotiation()) {
                    val (supportedVersions) = readVersionNegotiationPacket(it)
                    handler.versionNegotiationPacket(it.dstConnID, it.srcConnID, supportedVersions)
                } else {
                    when (it.getType()) {
                        Type.Initial -> {
                            val (token, packetNumber, payload) = readInitialPacket(it)
                            handler.initialPacket(it.dstConnID, it.srcConnID, token, packetNumber, payload)
                        }
                        Type.ZeroRTT -> {
                            val (packetNumber, payload) = readZeroRTTPacket(it)
                            handler.zeroRTTPacket(it.dstConnID, it.srcConnID, packetNumber, payload)
                        }
                        Type.Handshake -> {
                            val (packetNumber, payload) = readHandshakePacket(it)
                            handler.handshakePacket(it.dstConnID, it.srcConnID, packetNumber, payload)
                        }
                        Type.Retry -> {
                            val (token) = readRetryPacket(it)
                            handler.retryPacket(it.dstConnID, it.srcConnID, token)
                        }
                    }
                }
            }
        } else {
            readShortHeader().let {
                val packetNumber = source.readByteArray(it.getPacketNumberLength()).toUByteArray()
                val payload = Buffer()
                source.readAll(payload)

                handler.shortPacket(it.dstConnID, packetNumber, payload)
            }
        }
    }

    @Throws(IOException::class)
    private fun readLongHeader(): LongHeader {
        val flags = source.readByte().toUByte()
        val version = source.readInt().toUInt()
        val dstConnID = readConnectionID()
        val srcConnID = readConnectionID()
        return LongHeader(flags, version, dstConnID, srcConnID)
    }

    @Throws(IOException::class)
    private fun readConnectionID(): ConnectionID {
        val len = source.readByte().toUByte().toLong()
        return ConnectionID(source.readByteArray(len).toUByteArray())
    }

    @Throws(IOException::class)
    private fun readVersionNegotiationPacket(header: LongHeader): VersionNegotiationPacket {
        val supportedVersions = ArrayList<UInt>()
        do {
            supportedVersions.add(source.readInt().toUInt())
        } while (!source.exhausted())
        return VersionNegotiationPacket(supportedVersions.toUIntArray())
    }

    @Throws(IOException::class)
    private fun readInitialPacket(header: LongHeader): InitialPacket {
        val tokenLen = source.readVarUInt().toLong();
        val token = if (tokenLen == 0L) { null } else { source.readByteArray(tokenLen).toUByteArray() }
        val length = source.readVarUInt()
        val packetNumber = source.readByteArray(header.getPacketNumberLength()).toUByteArray()
        val payload = Buffer()
        source.readFully(payload, length)

        return InitialPacket(token, packetNumber, payload)
    }

    @Throws(IOException::class)
    private fun readZeroRTTPacket(header: LongHeader): ZeroRTTPacket {
        val length = source.readVarUInt()
        val packetNumber = source.readByteArray(header.getPacketNumberLength()).toUByteArray()
        val payload = Buffer()
        source.readFully(payload, length)

        return ZeroRTTPacket(packetNumber, payload)
    }

    @Throws(IOException::class)
    private fun readHandshakePacket(header: LongHeader): HandshakePacket {
        val length = source.readVarUInt()
        val packetNumber = source.readByteArray(header.getPacketNumberLength()).toUByteArray()
        val payload = Buffer()
        source.readFully(payload, length)

        return HandshakePacket(packetNumber, payload)
    }

    @Throws(IOException::class)
    private fun readRetryPacket(header: LongHeader): RetryPacket {
        val token = source.readByteArray().toUByteArray()

        return RetryPacket(token)
    }

    @Throws(IOException::class)
    private fun readShortHeader(): ShortHeader {
        val flags = source.readByte().toUByte()
        val dstConnID = readConnectionID()
        return ShortHeader(flags,  dstConnID)
    }
}