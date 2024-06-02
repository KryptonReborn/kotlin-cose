package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNull

data class COSEEncrypt0(
    val headers: Headers,
    val ciphertext: ByteArray? = null,
) : COSEItem {
    override fun serialize(): CborArray {
        val cborArray = CborArray()

        headers.serialize().forEach { header -> cborArray.add(header!!) }
        cborArray.add(ciphertext?.let { CborByteString(it) } ?: CborNull)

        return cborArray
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is COSEEncrypt0) return false

        return headers == other.headers &&
            ciphertext?.contentEquals(other.ciphertext ?: byteArrayOf()) ?: (other.ciphertext == null)
    }

    override fun hashCode(): Int {
        var result = headers.hashCode()
        result = 31 * result + (ciphertext?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(cborArray: CborArray): COSEEncrypt0 {
            val cborElements: List<CborElement> = cborArray.items()
            if (cborElements.size != 3) throw CborException("Deserialization error. Expected array size: 3, Found: ${cborElements.size}")

            val headers = Headers.deserialize(listOf(cborElements[0], cborElements[1]))
            val ciphertext: ByteArray? = (cborElements[2] as CborByteString).bytes

            return COSEEncrypt0(headers, ciphertext)
        }
    }
}
