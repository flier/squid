package squid

inline class ConnectionID(val id: ByteArray) {
    val size: Int
        get() = id.size
}

typealias StreamID = Long
typealias PacketNumber = Long
typealias SequenceNumber = Long
typealias Token = ByteArray

/**
 * QUIC Transport Error codes defined by the QUIC Transport RFC.
 */
typealias ErrorCode = Long

/**
 * An endpoint uses this with CONNECTION_CLOSE to signal that the connection
 * is being closed abruptly in the absence of any error.
 */
const val QUIC_ERROR_NO_ERROR = 0x0

/**
 * The endpoint encountered an unspecified internal error and cannot continue
 * with the connection.
 */
const val QUIC_ERROR_INTERNAL_ERROR = 0x1

/**
 * The server refused to accept the new connection.
 */
const val QUIC_ERROR_CONNECTION_REFUSED = 0x2

/**
 * An endpoint received more data than it permitted in its advertised data limits.
 */
const val QUIC_ERROR_FLOW_CONTROL_ERROR = 0x3

/**
 * An endpoint received a frame for a stream identifier that exceeded its
 * advertised limit for the corresponding stream type.
 */
const val QUIC_ERROR_STREAM_LIMIT_ERROR = 0x4

/**
 * An endpoint received a frame for a stream that was not in a state that permitted that frame.
 */
const val QUIC_ERROR_STREAM_STATE_ERROR = 0x5

/**
 * An endpoint received a STREAM frame containing data that exceeded the
 * previously established final size. Or an endpoint received a STREAM frame
 * or a RESET_STREAM frame containing a final size that was lower than the size
 * of stream data that was already received.  Or an endpoint received a STREAM
 * frame or a RESET_STREAM frame containing a different final size to the one
 * already established.
 */
const val QUIC_ERROR_FINAL_SIZE_ERROR = 0x6

/**
 * An endpoint received a frame that was badly formatted. For instance, an empty
 * STREAM frame that omitted the FIN flag, or an ACK frame that has more
 * acknowledgment ranges than the remainder of the packet could carry.
 */
const val QUIC_ERROR_FRAME_ENCODING_ERROR = 0x7

/**
 * An endpoint received transport parameters that were badly formatted, included
 * an invalid value, was absent even though it is mandatory, was present though
 * it is forbidden, or is otherwise in error.
 */
const val QUIC_ERROR_TRANSPORT_PARAMETER_ERROR = 0x8

/**
 * An endpoint detected an error with protocol compliance that was not covered
 * by more specific error codes.
 */
const val QUIC_ERROR_PROTOCOL_VIOLATION = 0xA

/**
 * An endpoint has received more data in CRYPTO frames than it can buffer.
 */
const val QUIC_ERROR_CRYPTO_BUFFER_EXCEEDED = 0xD

/**
 * An endpoint detected errors in performing key updates.
 */
const val QUIC_ERROR_KEY_UPDATE_ERROR = 0xE

/**
 * An endpoint has exceeded the maximum number of failed packet decryptions
 * over its lifetime.
 */
const val QUIC_ERROR_AEAD_LIMIT_REACHED = 0xF
