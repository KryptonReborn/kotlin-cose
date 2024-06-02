package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.MajorType

data class ProtectedHeaderMap(
    private val bytes: ByteArray = ByteArray(0),
) : COSEItem {
    constructor(headerMap: HeaderMap) : this(headerMap.serializeAsBytes())

    override fun serialize(): CborElement {
        return CborByteString(bytes)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ProtectedHeaderMap

        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    fun getAsHeaderMap(): HeaderMap {
        return try {
            val cborElement: CborElement = CborDecoder.decode(bytes)[0]
            HeaderMap.deserialize(cborElement)
        } catch (e: CborException) {
            throw CborException("Deserialization error", e)
        }
    }

    companion object {
        fun deserialize(cborElement: CborElement): ProtectedHeaderMap {
            if (cborElement.majorType == MajorType.BYTE_STRING) {
                val bytes: ByteArray = (cborElement as CborByteString).bytes!!
                return ProtectedHeaderMap(bytes)
            } else {
                throw CborException(
                    "Deserialization error: Invalid type for ProtectedHeaderMap, " +
                        "expected type: CborByteString, found type ${cborElement.majorType}",
                )
            }
        }
    }
}
