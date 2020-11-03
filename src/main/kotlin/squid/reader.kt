package squid

import java.io.Closeable
import java.io.IOException
import okio.BufferedSource
import okio.EOFException
import squid.Quic.FLAG_LONG_FORM
import squid.Quic.MIN_HEADER_SIZE

interface Handler {
    fun version_negotiation(supportedVersions: Array<UInt>)
}

@ExperimentalUnsignedTypes
class QuicReader(
    private val source: BufferedSource,
    private val client: Boolean,
) : Closeable {
    @Throws(IOException::class)
    override fun close() {
        source.close()
    }

    @Throws(IOException::class)
    fun nextFrame(handler: Handler): Boolean {
        try {
            source.require(MIN_HEADER_SIZE)
        } catch (e: EOFException) {
            return false
        }

        val header = readHeader()

        when {
            header.isVersionNegotiation() -> {
                val (supported_versions) = readVersionNegotiationPacket(header)
                handler.version_negotiation(supported_versions)
            }
            header.isLongForm() -> {
                when (header.getType()) {
                    Type.Initial -> readInitialPacket(header, handler)
                    Type.ZeroRTT -> readZeroRTTPacket(header, handler)
                    Type.Handshake -> readHandshakePacket(header, handler)
                    Type.Retry -> readRetryPacket(header, handler)
                }
            }
            else -> {
                readShortPacket(header, handler)
            }
        }

        return true
    }

    @Throws(IOException::class)
    private fun readHeader(): Header {
        val flags = source.readByte() and 0xff
        val version = source.readInt() and 0xffffffff
        val dstConnID = readConnectionID()
        val srcConnID = if (flags contains FLAG_LONG_FORM) { readConnectionID() } else { null }
        return Header(flags, version, dstConnID, srcConnID)
    }

    @Throws(IOException::class)
    private fun readConnectionID(): ConnectionID {
        val len = source.readByte().toUByte().toLong()
        return ConnectionID(source.readByteArray(len).toUByteArray())
    }

    @Throws(IOException::class)
    private fun readVersionNegotiationPacket(header: Header): VersionNegotiation {
        return VersionNegotiation(arrayOf())
    }

    @Throws(IOException::class)
    private fun readInitialPacket(header: Header, handler: Handler) {

    }

    @Throws(IOException::class)
    private fun readZeroRTTPacket(header: Header, handler: Handler) {

    }

    @Throws(IOException::class)
    private fun readHandshakePacket(header: Header, handler: Handler) {

    }

    @Throws(IOException::class)
    private fun readRetryPacket(header: Header, handler: Handler) {

    }

    @Throws(IOException::class)
    private fun readShortPacket(header: Header, handler: Handler) {

    }
}