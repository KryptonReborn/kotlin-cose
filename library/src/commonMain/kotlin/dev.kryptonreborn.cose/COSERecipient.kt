package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNull

data class COSERecipient(
    val headers: Headers,
    private val ciphertext: ByteArray? = null,
) : COSEItem {
    override fun serialize(): CborArray {
        val cosRecptArray = CborArray()

        headers.serialize().forEach { header -> cosRecptArray.add(header!!) }
        cosRecptArray.add(ciphertext?.let { CborByteString(it) } ?: CborNull)

        return cosRecptArray
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as COSERecipient

        return headers == other.headers &&
            (ciphertext?.contentEquals(other.ciphertext) ?: (other.ciphertext == null))
    }

    override fun hashCode(): Int {
        var result = headers.hashCode()
        result = 31 * result + (ciphertext?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(coseRecptArray: CborArray): COSERecipient {
            val dataItems: List<CborElement> = coseRecptArray.items()
            if (dataItems.size != 3) {
                throw CborException(
                    "Deserialization error. Expected array size: 3, Found: ${dataItems.size}",
                )
            }

            val headers = Headers.deserialize(listOf(dataItems[0], dataItems[1]))
            val ciphertext: ByteArray? = (dataItems[2] as CborByteString).bytes

            return COSERecipient(headers, ciphertext)
        }
    }
}
