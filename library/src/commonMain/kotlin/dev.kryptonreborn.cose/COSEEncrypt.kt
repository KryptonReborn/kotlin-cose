package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNull

data class COSEEncrypt(
    val headers: Headers,
    val ciphertext: ByteArray? = null,
    val recipients: List<COSERecipient> = listOf(),
) : COSEItem {
    override fun serialize(): CborArray {
        val cborArray = CborArray()

        headers.serialize().forEach { header -> cborArray.add(header!!) }
        cborArray.add(ciphertext?.let { CborByteString(it) } ?: CborNull)

        if (recipients.isNotEmpty()) {
            val rcptArray = CborArray()
            recipients.forEach { coseRecipient -> rcptArray.add(coseRecipient.serialize()) }

            cborArray.add(rcptArray)
        } else {
            throw CborException("Serialization error. At least 1 recipient is required.")
        }

        return cborArray
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as COSEEncrypt

        return headers == other.headers && ciphertext?.contentEquals(other.ciphertext)
            ?: (other.ciphertext == null) && recipients == other.recipients
    }

    override fun hashCode(): Int {
        var result = headers.hashCode()
        result = 31 * result + (ciphertext?.contentHashCode() ?: 0)
        result = 31 * result + recipients.hashCode()
        return result
    }

    companion object {
        fun deserialize(cborArray: CborArray): COSEEncrypt {
            val cborElements: List<CborElement> = cborArray.items()
            if (cborElements.size != 4) throw CborException("Deserialization error. Expected array size: 4, Found: ${cborElements.size}")

            val headers: Headers = Headers.deserialize(listOf(cborElements[0], cborElements[1]))
            val ciphertext: ByteArray? = (cborElements[2] as CborByteString).bytes

            val recipients: MutableList<COSERecipient> =
                (cborElements[3] as CborArray).items()
                    .map { cborElement -> COSERecipient.deserialize(cborElement as CborArray) }
                    .toMutableList()

            return COSEEncrypt(headers, ciphertext, recipients)
        }
    }
}
