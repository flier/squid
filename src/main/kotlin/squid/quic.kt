package squid

import okio.BufferedSource

data class ConnectionID(
    @JvmField val id: UByteArray
) {}

// The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers.
const val FLAG_LONG_FORM = 0x80
// The next bit (0x40) of byte 0 is set to 1.
//
// Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.
const val FLAG_FIXED = 0x40
// The next two bits (those with a mask of 0x30) of byte 0 contain a packet type.
const val FLAG_TYPE_MASK = 0x30
const val FLAG_TYPE_SHIFT = 4

// In packet types that contain a Packet Number field,
// the least significant two bits (those with a mask of 0x03) of byte 0 contain the length of the packet number,
// encoded as an unsigned, two-bit integer that is one less than the length of the packet number field in bytes.
const val FLAG_PACKET_NUMBER_LENGTH_MASK = 0x03

const val FLAG_SPIN = 0x20
// Allows a recipient of a packet to identify the packet protection keys that are used to protect the packet.
const val FLAG_KEY_PHASE = 0x04

const val TYPE_INITIAL = 0x0
const val TYPE_0RTT = 0x01
const val TYPE_HANDSHAKE = 0x02
const val TYPE_RETRY = 0x03

const val MAX_CONNECTION_ID_LENGTH = 20

object Quic {

}