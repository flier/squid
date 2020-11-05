package squid

import okio.Buffer
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
const val QUIC_STATELESS_RESET_TOKEN_LENGTH = 16L

/**
 * The size of the path challenge arbitrary data.
 */
const val QUIC_PATH_CHALLENGE_DATA_LENGTH = 8L

interface Frame {
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
) : Frame

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
) : Frame

data class StopSending(
    @JvmField val streamID: StreamID,
    @JvmField val errorCode: ErrorCode,
) : Frame

data class Crypto(
    @JvmField val offset: Long,
    @JvmField val length: Long,
    @JvmField val data: Buffer,
) : Frame

data class NewToken(
    @JvmField val token: Token,
) : Frame

data class Stream(
    @JvmField val fin: Boolean,
    @JvmField val streamID: StreamID,
    @JvmField val offset: Long?,
    @JvmField val data: Buffer,
) : Frame

data class MaxData(
    @JvmField val maximumData: Long,
) : Frame

data class MaxStreamData(
    @JvmField val streamID: StreamID,
    @JvmField val maximumData: Long,
) : Frame

data class MaxStreams(
    @JvmField val bidirectionalStreams: Boolean,
    @JvmField val maximumStreams: Long,
) : Frame

data class DataBlocked(
    @JvmField val dataLimit: Long,
) : Frame

data class StreamDataBlocked(
    @JvmField val streamID: StreamID,
    @JvmField val streamDataLimit: Long,
) : Frame

data class StreamsBlocked(
    @JvmField val bidirectionalStreams: Boolean,
    @JvmField val streamLimit: Long,
) : Frame

data class NewConnectionID(
    @JvmField val sequenceNumber: SequenceNumber,
    @JvmField val retirePriorTo: Long,
    @JvmField val connectionID: ConnectionID,
    @JvmField val statelessResetToken: Token,
) : Frame

data class RetireConnectionID(
    @JvmField val sequenceNumber: SequenceNumber,
) : Frame

data class PathChallenge(
    @JvmField val data: ByteArray,
) : Frame

data class PathResponse(
    @JvmField val data: ByteArray,
) : Frame

data class ConnectionClose(
    @JvmField val errorCode: ErrorCode,
    @JvmField val frameType: Int?,
    @JvmField val reasonPhrase: String?,
) : Frame

class FrameReader(
    private val source: BufferedSource,
    private val handler: Frame.Handler,
) : Closeable {
    @Throws(IOException::class)
    override fun close() = source.close()

    @Throws(IOException::class)
    fun nextFrame() {
        source.run {
            when (val frameType = peekFrameType()) {
                QUIC_FRAME_PADDING -> handler.padding()
                QUIC_FRAME_PING -> handler.ping()
                QUIC_FRAME_ACK, QUIC_FRAME_ACK_1 -> {
                    val (largestAcknowledged, ackDelay, firstAckBlock, ackBlocks, ecn) = readAckFrame(frameType)
                    handler.ack(largestAcknowledged, ackDelay, firstAckBlock, ackBlocks, ecn)
                }
                QUIC_FRAME_RESET_STREAM -> {
                    val (streamID, errorCode, finalSize) = readResetStream()
                    handler.resetStream(streamID, errorCode, finalSize)
                }
                QUIC_FRAME_STOP_SENDING -> {
                    val (streamID, errorCode) = readStopSending()
                    handler.stopSending(streamID, errorCode)
                }
                QUIC_FRAME_CRYPTO -> {
                    val (offset, length, data) = readCrypto()
                    handler.crypto(offset, length, data)
                }
                QUIC_FRAME_NEW_TOKEN -> {
                    val (token) = readNewToken()
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
                    val (fin, streamID, offset, data) = readStream(frameType)
                    handler.stream(fin, streamID, offset, data)
                }
                QUIC_FRAME_MAX_DATA -> {
                    val (maximumData) = readMaxData()
                    handler.maxData(maximumData)
                }
                QUIC_FRAME_MAX_STREAM_DATA -> {
                    val (streamID, maximumData) = readMaxStreamData()
                    handler.maxStreamData(streamID, maximumData)
                }
                QUIC_FRAME_MAX_STREAMS,
                QUIC_FRAME_MAX_STREAMS_1 -> {
                    val (bidirectionalStreams, maximumStreams) = readMaxStreams(frameType)
                    handler.maxStreams(bidirectionalStreams, maximumStreams)
                }
                QUIC_FRAME_DATA_BLOCKED -> {
                    val (dataLimit) = readDataBlocked()
                    handler.dataBlocked(dataLimit)
                }
                QUIC_FRAME_STREAM_DATA_BLOCKED -> {
                    val (streamID, dataLimit) = readStreamDataBlocked()
                    handler.streamDataBlocked(streamID, dataLimit)
                }
                QUIC_FRAME_STREAMS_BLOCKED,
                QUIC_FRAME_STREAMS_BLOCKED_1 -> {
                    val (bidirectionalStreams, streamLimit) = readStreamsBlocked(frameType)
                    handler.streamsBlocked(bidirectionalStreams, streamLimit)
                }
                QUIC_FRAME_NEW_CONNECTION_ID -> {
                    val (sequenceNumber, retirePriorTo, connectionID, statelessResetToken) = readNewConnectionID()
                    handler.newConnectionID(sequenceNumber, retirePriorTo, connectionID, statelessResetToken)
                }
                QUIC_FRAME_RETIRE_CONNECTION_ID -> {
                    val (sequenceNumber) = readRetireConnectionID()
                    handler.retireConnectionID(sequenceNumber)
                }
                QUIC_FRAME_PATH_CHALLENGE -> {
                    val (data) = readPathChallenge()
                    handler.pathChallenge(data)
                }
                QUIC_FRAME_PATH_RESPONSE -> {
                    val (data) = readPathResponse()
                    handler.pathResponse(data)
                }
                QUIC_FRAME_CONNECTION_CLOSE,
                QUIC_FRAME_CONNECTION_CLOSE_1 -> {
                    val (errorCode, frameType, reasonPhrase) = readConnectionClose(frameType)
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
fun BufferedSource.peekFrameType() = peek().readByte().toUByte().toInt()

@Throws(IOException::class)
fun BufferedSource.readAckFrame(frameType: Int): Ack {
    val largestAcknowledged = readVarUInt()
    val ackDelay = readVarUInt()
    val count = readVarUInt()
    val firstAckBlock = readVarUInt()
    val ackBlocks = Array<AckRange>(count.toInt()) { readAckRange() }
    val ecn = if (frameType == QUIC_FRAME_ACK_1) {
        readAckECN()
    } else {
        null
    }

    return Ack(largestAcknowledged, ackDelay, firstAckBlock, ackBlocks, ecn)
}

@Throws(IOException::class)
fun BufferedSource.readAckRange() = AckRange(readVarUInt(), readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readAckECN() = AckECN(readVarUInt(), readVarUInt(), readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readResetStream() = ResetStream(readVarUInt(), readVarUInt(), readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readStopSending() = StopSending(readVarUInt(), readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readCrypto(): Crypto {
    val offset = readVarUInt()
    val length = readVarUInt()
    val data = Buffer()
    readFully(data, length)

    return Crypto(offset, length, data)
}

@Throws(IOException::class)
fun BufferedSource.readNewToken() = NewToken(readByteArray(readVarUInt()))

@Throws(IOException::class)
fun BufferedSource.readStream(frameType: Int): Stream {
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

    return Stream(fin, id, offset, data)
}

@Throws(IOException::class)
fun BufferedSource.readMaxData() = MaxData(readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readMaxStreamData() = MaxStreamData(readVarUInt(), readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readMaxStreams(frameType: Int) = MaxStreams(frameType == QUIC_FRAME_MAX_STREAMS, readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readDataBlocked() = DataBlocked(readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readStreamDataBlocked() = StreamDataBlocked(readVarUInt(), readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readStreamsBlocked(frameType: Int) =
    StreamsBlocked(frameType == QUIC_FRAME_STREAMS_BLOCKED, readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readNewConnectionID() =
    NewConnectionID(readVarUInt(), readVarUInt(), readConnectionID(), readByteArray(QUIC_STATELESS_RESET_TOKEN_LENGTH))

@Throws(IOException::class)
fun BufferedSource.readRetireConnectionID() = RetireConnectionID(readVarUInt())

@Throws(IOException::class)
fun BufferedSource.readPathChallenge() = PathChallenge(readByteArray(QUIC_PATH_CHALLENGE_DATA_LENGTH))

@Throws(IOException::class)
fun BufferedSource.readPathResponse() = PathResponse(readByteArray(QUIC_PATH_CHALLENGE_DATA_LENGTH))

@Throws(IOException::class)
fun BufferedSource.readConnectionClose(frameType: Int) = ConnectionClose(
    readVarUInt(),
    if (frameType == QUIC_FRAME_CONNECTION_CLOSE) {
        readVarUInt().toInt()
    } else {
        null
    },
    readString(),
)

@Throws(IOException::class)
fun BufferedSource.readString() = readVarUInt().let {
    if (it == 0L) {
        null
    } else {
        readUtf8(it)
    }
}