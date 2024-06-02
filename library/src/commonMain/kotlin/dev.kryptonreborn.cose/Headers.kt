package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborMap

data class Headers(
    val protected: ProtectedHeaderMap? = null,
    val unprotected: HeaderMap? = null,
) {
    fun serialize(): Array<CborElement?> {
        val cborElements: Array<CborElement?> = arrayOfNulls(2)

        cborElements[0] = protected?.serialize() ?: CborByteString(ByteArray(0))
        cborElements[1] = unprotected?.serialize() ?: CborMap()

        return cborElements
    }

    companion object {
        fun deserialize(items: List<CborElement?>): Headers {
            if (items.size != 2) {
                throw CborException("Deserialization error. Invalid array size. Expected size: 2, Found: ${items.size}")
            }

            return Headers(
                protected = ProtectedHeaderMap.deserialize(items[0]!!),
                unprotected = HeaderMap.deserialize(items[1]!!),
            )
        }
    }
}
