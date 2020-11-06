package squid

import okio.Buffer
import okio.BufferedSink
import okio.BufferedSource
import java.io.Closeable
import java.io.IOException

const val QUIC_FRAME_PADDING = 0x0
const val QUIC_FRAME_PING = 0x1
const val QUIC_FRAME_ACK = 0x2 // to 0x3
const val QUIC_FRAME_ACK_1 = 0x3
const val QUIC_FRAME_RESET_STREAM = 0x4
const val QUIC_FRAME_STOP_SENDING = 0x5
const val QUIC_FRAME_CRYPTO = 0x6
const val QUIC_FRAME_NEW_TOKEN = 0x7
const val QUIC_FRAME_STREAM = 0x8 // to 0xf
const val QUIC_FRAME_STREAM_1 = 0x9
const val QUIC_FRAME_STREAM_2 = 0xa
const val QUIC_FRAME_STREAM_3 = 0xb
const val QUIC_FRAME_STREAM_4 = 0xc
const val QUIC_FRAME_STREAM_5 = 0xd
const val QUIC_FRAME_STREAM_6 = 0xe
const val QUIC_FRAME_STREAM_7 = 0xf
const val QUIC_FRAME_MAX_DATA = 0x10
const val QUIC_FRAME_MAX_STREAM_DATA = 0x11
const val QUIC_FRAME_MAX_STREAMS = 0x12 // to 0x13
const val QUIC_FRAME_MAX_STREAMS_1 = 0x13
const val QUIC_FRAME_DATA_BLOCKED = 0x14
const val QUIC_FRAME_STREAM_DATA_BLOCKED = 0x15
const val QUIC_FRAME_STREAMS_BLOCKED = 0x16 // to 0x17
const val QUIC_FRAME_STREAMS_BLOCKED_1 = 0x17
const val QUIC_FRAME_NEW_CONNECTION_ID = 0x18
const val QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19
const val QUIC_FRAME_PATH_CHALLENGE = 0x1a
const val QUIC_FRAME_PATH_RESPONSE = 0x1b
const val QUIC_FRAME_CONNECTION_CLOSE = 0x1c // to 0x1d
const val QUIC_FRAME_CONNECTION_CLOSE_1 = 0x1d
const val QUIC_FRAME_HANDSHAKE_DONE = 0x1e

/* 0x1f to 0x2f are unused currently */
const val QUIC_FRAME_DATAGRAM = 0x30 // to 0x31
const val QUIC_FRAME_DATAGRAM_1 = 0x31

const val QUIC_STREAM_FLAG_MASK = 0x07
const val QUIC_STREAM_FLAG_OFF = 0x04
const val QUIC_STREAM_FLAG_LEN = 0x02
const val QUIC_STREAM_FLAG_FIN = 0x01

/**
 * The size of the stateless reset token.
 */
const val QUIC_STATELESS_RESET_TOKEN_LENGTH = 16

/**
 * The size of the path challenge arbitrary data.
 */
const val QUIC_PATH_CHALLENGE_DATA_LENGTH = 8L

const val FRAME_TYPE_SIZE = UByte.SIZE_BYTES

interface Frame : Writable {
    interface Handler {
        fun padding() {}

        fun ping() {}

        fun ack(
            largestAcknowledged: Long,
            ackDelay: Long,
            firstAckBlock: Long,
            ackBlocks: Array<AckRange>,
            ecn: AckECN?
        ) {
        }

        fun resetStream(streamID: StreamID, errorCode: ErrorCode, finalSize: Long) {}

        fun stopSending(streamID: StreamID, errorCode: ErrorCode) {}

        fun crypto(offset: Long, length: Long, data: Buffer) {}

        fun newToken(token: Token) {}

        fun stream(fin: Boolean, streamID: StreamID, offset: Long?, data: Buffer) {}

        fun maxData(maximumData: Long) {}

        fun maxStreamData(streamID: StreamID, maximumData: Long) {}

        fun maxStreams(bidirectionalStreams: Boolean, maximumStreams: Long) {}

        fun dataBlocked(dataLimit: Long) {}

        fun streamDataBlocked(streamID: StreamID, dataLimit: Long) {}

        fun streamsBlocked(bidirectionalStreams: Boolean, streamLimit: Long) {}

        fun newConnectionID(
            sequenceNumber: SequenceNumber,
            retirePriorTo: Long,
            connectionID: ConnectionID,
            statelessResetToken: Token
        ) {
        }

        fun retireConnectionID(sequenceNumber: SequenceNumber) {}

        fun pathChallenge(data: ByteArray) {}

        fun pathResponse(data: ByteArray) {}

        fun connectionClose(errorCode: ErrorCode, frameType: Int?, reasonPhrase: String?) {}

        fun handshakeDone() {}
    }
}

data class Ack(
    @JvmField val largestAcknowledged: Long,
    @JvmField val ackDelay: Long,
    @JvmField val firstAckBlock: Long,
    @JvmField val ackBlocks: Array<AckRange>,
    @JvmField val ecn: AckECN?,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(largestAcknowledged) +
                VarInt.sizeOf(ackDelay) +
                VarInt.sizeOf(ackBlocks.size.toLong()) +
                VarInt.sizeOf(firstAckBlock) +
                ackBlocks.sumBy {
                    VarInt.sizeOf(it.gap) + VarInt.sizeOf(it.ackBlock)
                } +
                if (ecn == null) {
                    0
                } else {
                    VarInt.sizeOf(ecn.ect0) + VarInt.sizeOf(ecn.ect1) + VarInt.sizeOf(ecn.ce)
                }
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(
            if (ecn == null) {
                QUIC_FRAME_ACK
            } else {
                QUIC_FRAME_ACK_1
            }
        )
        writeVarUInt(largestAcknowledged, ackDelay, ackBlocks.size.toLong(), firstAckBlock)
        ackBlocks.forEach {
            writeVarUInt(it.gap, it.ackBlock)
        }
        if (ecn != null) {
            writeVarUInt(ecn.ect0, ecn.ect1, ecn.ce)
        }
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType in QUIC_FRAME_ACK..QUIC_FRAME_ACK_1)

            val largestAcknowledged = readVarUInt()
            val ackDelay = readVarUInt()
            val count = readVarUInt()
            val firstAckBlock = readVarUInt()
            val ackBlocks = Array(count.toInt()) {
                AckRange(readVarUInt(), readVarUInt())
            }
            val ecn = if (frameType == QUIC_FRAME_ACK_1) {
                AckECN(readVarUInt(), readVarUInt(), readVarUInt())
            } else {
                null
            }

            Ack(largestAcknowledged, ackDelay, firstAckBlock, ackBlocks, ecn)
        }
    }
}

data class AckRange(
    @JvmField val gap: Long,
    @JvmField val ackBlock: Long,
)

data class AckECN(
    @JvmField val ect0: Long,
    @JvmField val ect1: Long,
    @JvmField val ce: Long,
)

data class ResetStream(
    @JvmField val streamID: StreamID,
    @JvmField val errorCode: ErrorCode,
    @JvmField val finalSize: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(streamID) +
                VarInt.sizeOf(errorCode) +
                VarInt.sizeOf(finalSize)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_RESET_STREAM)
        writeVarUInt(streamID, errorCode, finalSize)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_RESET_STREAM)
            ResetStream(readVarUInt(), readVarUInt(), readVarUInt())
        }
    }
}

data class StopSending(
    @JvmField val streamID: StreamID,
    @JvmField val errorCode: ErrorCode,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(streamID) +
                VarInt.sizeOf(errorCode)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_STOP_SENDING)
        writeVarUInt(streamID, errorCode)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_STOP_SENDING)
            StopSending(readVarUInt(), readVarUInt())
        }
    }
}

data class Crypto(
    @JvmField val offset: Long,
    @JvmField val length: Long,
    @JvmField val data: Buffer,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(offset) +
                VarInt.sizeOf(length) +
                data.size.toInt()
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_CRYPTO)
        writeVarUInt(offset, length)
        write(data, length)
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_CRYPTO)
            val offset = readVarUInt()
            val length = readVarUInt()
            val data = Buffer()
            readFully(data, length)

            Crypto(offset, length, data)
        }
    }
}

data class NewToken(
    @JvmField val token: Token,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(token.size.toLong()) +
                token.size
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_NEW_TOKEN)
        writeVarUInt(token.size.toLong())
        write(token)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_NEW_TOKEN)
            NewToken(readByteArray(readVarUInt()))
        }
    }
}

data class Stream(
    @JvmField val fin: Boolean,
    @JvmField val streamID: StreamID,
    @JvmField val offset: Long?,
    @JvmField val data: Buffer,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(streamID) +
                if (offset == null) {
                    0
                } else {
                    VarInt.sizeOf(offset)
                } +
                VarInt.sizeOf(data.size) +
                data.size.toInt()
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        var frameType = QUIC_FRAME_STREAM or QUIC_STREAM_FLAG_LEN
        if (fin) {
            frameType = frameType or QUIC_STREAM_FLAG_FIN
        }
        if (offset != null) {
            frameType = frameType or QUIC_STREAM_FLAG_OFF
        }
        writeByte(frameType)
        writeVarUInt(streamID)
        if (offset != null) {
            writeVarUInt(offset)
        }
        writeVarUInt(data.size)
        write(data, data.size)
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType in QUIC_FRAME_STREAM..QUIC_FRAME_STREAM_7)
            val flags = frameType.toUByte() and QUIC_STREAM_FLAG_MASK
            val off = flags contains QUIC_STREAM_FLAG_OFF
            val len = flags contains QUIC_STREAM_FLAG_LEN
            val fin = flags contains QUIC_STREAM_FLAG_FIN

            val id = readVarUInt()
            val offset = if (off) {
                readVarUInt()
            } else {
                null
            }
            val data = Buffer()
            if (len) {
                readFully(data, readVarUInt())
            } else {
                readAll(data)
            }

            Stream(fin, id, offset, data)
        }
    }
}

data class MaxData(
    @JvmField val maximumData: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(maximumData)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_MAX_DATA)
        writeVarUInt(maximumData)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_MAX_DATA)
            MaxData(readVarUInt())
        }
    }
}

data class MaxStreamData(
    @JvmField val streamID: StreamID,
    @JvmField val maximumData: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(streamID) + VarInt.sizeOf(maximumData)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_MAX_STREAM_DATA)
        writeVarUInt(streamID, maximumData)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_MAX_STREAM_DATA)
            MaxStreamData(readVarUInt(), readVarUInt())
        }
    }
}

data class MaxStreams(
    @JvmField val bidirectionalStreams: Boolean,
    @JvmField val maximumStreams: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(maximumStreams)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(
            if (bidirectionalStreams) {
                QUIC_FRAME_MAX_STREAMS
            } else {
                QUIC_FRAME_MAX_STREAMS_1
            }
        )
        writeVarUInt(maximumStreams)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType in QUIC_FRAME_MAX_STREAMS..QUIC_FRAME_MAX_STREAMS_1)
            MaxStreams(frameType == QUIC_FRAME_MAX_STREAMS, readVarUInt())
        }
    }
}

data class DataBlocked(
    @JvmField val dataLimit: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(dataLimit)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_DATA_BLOCKED)
        writeVarUInt(dataLimit)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_DATA_BLOCKED)
            DataBlocked(readVarUInt())
        }
    }
}

data class StreamDataBlocked(
    @JvmField val streamID: StreamID,
    @JvmField val streamDataLimit: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(streamID) + VarInt.sizeOf(streamDataLimit)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_STREAM_DATA_BLOCKED)
        writeVarUInt(streamID, streamDataLimit)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_STREAM_DATA_BLOCKED)
            StreamDataBlocked(readVarUInt(), readVarUInt())
        }
    }
}

data class StreamsBlocked(
    @JvmField val bidirectionalStreams: Boolean,
    @JvmField val streamLimit: Long,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(streamLimit)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(
            if (bidirectionalStreams) {
                QUIC_FRAME_STREAMS_BLOCKED
            } else {
                QUIC_FRAME_STREAMS_BLOCKED_1
            }
        )
        writeVarUInt(streamLimit)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType in QUIC_FRAME_STREAMS_BLOCKED..QUIC_FRAME_STREAMS_BLOCKED_1)
            StreamsBlocked(frameType == QUIC_FRAME_STREAMS_BLOCKED, readVarUInt())
        }
    }
}

data class NewConnectionID(
    @JvmField val sequenceNumber: SequenceNumber,
    @JvmField val retirePriorTo: Long,
    @JvmField val connectionID: ConnectionID,
    @JvmField val statelessResetToken: Token,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(sequenceNumber) + VarInt.sizeOf(retirePriorTo) + QUIC_STATELESS_RESET_TOKEN_LENGTH
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_NEW_CONNECTION_ID)
        writeVarUInt(sequenceNumber, retirePriorTo)
        writeConnectionID(connectionID)
        write(statelessResetToken)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_NEW_CONNECTION_ID)
            NewConnectionID(
                readVarUInt(),
                readVarUInt(),
                readConnectionID(),
                readByteArray(QUIC_STATELESS_RESET_TOKEN_LENGTH.toLong()),
            )
        }
    }
}

data class RetireConnectionID(
    @JvmField val sequenceNumber: SequenceNumber,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + VarInt.sizeOf(sequenceNumber)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_RETIRE_CONNECTION_ID)
        writeVarUInt(sequenceNumber)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_RETIRE_CONNECTION_ID)
            RetireConnectionID(readVarUInt())
        }
    }
}

data class PathChallenge(
    @JvmField val data: ByteArray,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + data.size
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_PATH_CHALLENGE)
        write(data)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_PATH_CHALLENGE)
            PathChallenge(readByteArray(QUIC_PATH_CHALLENGE_DATA_LENGTH))
        }
    }
}

data class PathResponse(
    @JvmField val data: ByteArray,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE + data.size
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(QUIC_FRAME_PATH_RESPONSE)
        write(data)
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType == QUIC_FRAME_PATH_RESPONSE)
            PathResponse(readByteArray(QUIC_PATH_CHALLENGE_DATA_LENGTH))
        }
    }
}

data class ConnectionClose(
    @JvmField val errorCode: ErrorCode,
    @JvmField val frameType: Int?,
    @JvmField val reasonPhrase: String?,
) : Frame {
    override val size: Int by lazy {
        FRAME_TYPE_SIZE +
                VarInt.sizeOf(errorCode) +
                if (frameType == null) {
                    0
                } else {
                    VarInt.sizeOf(frameType.toLong())
                } +
                1 + (reasonPhrase?.length ?: 0)
    }

    @Throws(IOException::class)
    override fun writeTo(sink: BufferedSink) = sink.run {
        writeByte(
            if (frameType != null) {
                QUIC_FRAME_CONNECTION_CLOSE
            } else {
                QUIC_FRAME_CONNECTION_CLOSE_1
            }
        )
        writeVarUInt(errorCode)
        if (frameType != null) {
            writeVarUInt(frameType.toLong())
        }
        if (reasonPhrase != null) {
            writeString(reasonPhrase)
        } else {
            writeByte(0)
        }
        sink
    }

    companion object {
        @Throws(IOException::class)
        fun read(source: BufferedSource) = source.run {
            val frameType = readFrameType()
            assert(frameType in QUIC_FRAME_CONNECTION_CLOSE..QUIC_FRAME_CONNECTION_CLOSE_1)
            ConnectionClose(
                readVarUInt(),
                if (frameType == QUIC_FRAME_CONNECTION_CLOSE) {
                    readVarUInt().toInt()
                } else {
                    null
                },
                readString(),
            )
        }
    }
}

class FrameReader(
    private val source: BufferedSource,
    private val handler: Frame.Handler,
) : Closeable {
    @Throws(IOException::class)
    override fun close() = source.close()

    @Throws(IOException::class)
    fun nextFrame() {
        source.run {
            when (peekFrameType()) {
                QUIC_FRAME_PADDING -> handler.padding()
                QUIC_FRAME_PING -> handler.ping()
                QUIC_FRAME_ACK, QUIC_FRAME_ACK_1 -> {
                    val (largestAcknowledged, ackDelay, firstAckBlock, ackBlocks, ecn) = Ack.read(source)
                    handler.ack(largestAcknowledged, ackDelay, firstAckBlock, ackBlocks, ecn)
                }
                QUIC_FRAME_RESET_STREAM -> {
                    val (streamID, errorCode, finalSize) = ResetStream.read(source)
                    handler.resetStream(streamID, errorCode, finalSize)
                }
                QUIC_FRAME_STOP_SENDING -> {
                    val (streamID, errorCode) = StopSending.read(source)
                    handler.stopSending(streamID, errorCode)
                }
                QUIC_FRAME_CRYPTO -> {
                    val (offset, length, data) = Crypto.read(source)
                    handler.crypto(offset, length, data)
                }
                QUIC_FRAME_NEW_TOKEN -> {
                    val (token) = NewToken.read(source)
                    handler.newToken(token)
                }
                QUIC_FRAME_STREAM,
                QUIC_FRAME_STREAM_1,
                QUIC_FRAME_STREAM_2,
                QUIC_FRAME_STREAM_3,
                QUIC_FRAME_STREAM_4,
                QUIC_FRAME_STREAM_5,
                QUIC_FRAME_STREAM_6,
                QUIC_FRAME_STREAM_7 -> {
                    val (fin, streamID, offset, data) = Stream.read(source)
                    handler.stream(fin, streamID, offset, data)
                }
                QUIC_FRAME_MAX_DATA -> {
                    val (maximumData) = MaxData.read(source)
                    handler.maxData(maximumData)
                }
                QUIC_FRAME_MAX_STREAM_DATA -> {
                    val (streamID, maximumData) = MaxStreamData.read(source)
                    handler.maxStreamData(streamID, maximumData)
                }
                QUIC_FRAME_MAX_STREAMS,
                QUIC_FRAME_MAX_STREAMS_1 -> {
                    val (bidirectionalStreams, maximumStreams) = MaxStreams.read(source)
                    handler.maxStreams(bidirectionalStreams, maximumStreams)
                }
                QUIC_FRAME_DATA_BLOCKED -> {
                    val (dataLimit) = DataBlocked.read(source)
                    handler.dataBlocked(dataLimit)
                }
                QUIC_FRAME_STREAM_DATA_BLOCKED -> {
                    val (streamID, dataLimit) = StreamDataBlocked.read(source)
                    handler.streamDataBlocked(streamID, dataLimit)
                }
                QUIC_FRAME_STREAMS_BLOCKED,
                QUIC_FRAME_STREAMS_BLOCKED_1 -> {
                    val (bidirectionalStreams, streamLimit) = StreamsBlocked.read(source)
                    handler.streamsBlocked(bidirectionalStreams, streamLimit)
                }
                QUIC_FRAME_NEW_CONNECTION_ID -> {
                    val (sequenceNumber, retirePriorTo, connectionID, statelessResetToken) = NewConnectionID.read(source)
                    handler.newConnectionID(sequenceNumber, retirePriorTo, connectionID, statelessResetToken)
                }
                QUIC_FRAME_RETIRE_CONNECTION_ID -> {
                    val (sequenceNumber) = RetireConnectionID.read(source)
                    handler.retireConnectionID(sequenceNumber)
                }
                QUIC_FRAME_PATH_CHALLENGE -> {
                    val (data) = PathChallenge.read(source)
                    handler.pathChallenge(data)
                }
                QUIC_FRAME_PATH_RESPONSE -> {
                    val (data) = PathResponse.read(source)
                    handler.pathResponse(data)
                }
                QUIC_FRAME_CONNECTION_CLOSE,
                QUIC_FRAME_CONNECTION_CLOSE_1 -> {
                    val (errorCode, frameType, reasonPhrase) = ConnectionClose.read(source)
                    handler.connectionClose(errorCode, frameType, reasonPhrase)
                }
                QUIC_FRAME_HANDSHAKE_DONE -> {
                    handler.handshakeDone()
                }
            }
        }
    }
}

@Throws(IOException::class)
fun BufferedSource.peekFrameType() = peek().readFrameType()

@Throws(IOException::class)
fun BufferedSource.readFrameType() = readByte().toUByte().toInt()

@Throws(IOException::class)
fun BufferedSource.readString() = readVarUInt().let {
    if (it == 0L) {
        null
    } else {
        readUtf8(it)
    }
}

@Throws(IOException::class)
fun BufferedSink.writeString(s: String) = writeVarUInt(s.length.toLong()).writeUtf8(s)