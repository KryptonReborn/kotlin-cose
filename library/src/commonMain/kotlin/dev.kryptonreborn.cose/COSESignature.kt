package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.MajorType

data class COSESignature(
    val headers: Headers? = null,
    val signature: ByteArray? = null,
) : COSEItem {
    override fun serialize(): CborElement {
        val cborArray = CborArray()
        headers?.serialize()?.forEach { headerItem -> cborArray.add(headerItem!!) }
        cborArray.add(CborByteString(signature))
        return cborArray
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as COSESignature

        return headers == other.headers &&
            (signature?.contentEquals(other.signature) ?: (other.signature == null))
    }

    override fun hashCode(): Int {
        var result = headers?.hashCode() ?: 0
        result = 31 * result + (signature?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(cborElement: CborElement): COSESignature {
            if (MajorType.ARRAY != cborElement.majorType) {
                throw CborException(
                    "Deserialization error. Expected type: Array, Found: ${cborElement.majorType}",
                )
            }

            val coseSigDIs: List<CborElement> =
                (cborElement as CborArray).items() // Size should be 3, 2 from Headers.kt and 1 signature

            if (coseSigDIs.size != 3) {
                throw CborException(
                    "Deserialization error: Invalid array size. Expected: 3, Found: ${coseSigDIs.size}",
                )
            }

            val headers = Headers.deserialize(listOf(coseSigDIs[0], coseSigDIs[1]))
            val signature = (coseSigDIs[2] as CborByteString).bytes!!

            return COSESignature(headers, signature)
        }
    }
}
