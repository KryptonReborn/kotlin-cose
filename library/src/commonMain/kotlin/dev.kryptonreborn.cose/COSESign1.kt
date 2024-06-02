package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNull
import dev.kryptonreborn.cbor.model.MajorType

data class COSESign1(
    val headers: Headers? = null,
    val payload: ByteArray? = null,
    val signature: ByteArray? = null,
) : COSEItem {
    override fun serialize(): CborArray {
        val cborArray = CborArray()
        headers?.serialize()?.forEach { headerItem -> cborArray.add(headerItem!!) }

        if (payload != null && payload.isNotEmpty()) {
            cborArray.add(CborByteString(payload))
        } else {
            cborArray.add(CborNull)
        }

        if (signature != null) {
            cborArray.add(CborByteString(signature))
        } else {
            cborArray.add(CborByteString(ByteArray(0)))
        }

        return cborArray
    }

    fun signedData(
        externalAad: ByteArray? = null,
        externalPayload: ByteArray? = null,
    ): SigStructure {
        val payload: ByteArray =
            externalPayload?.copyOf() ?: payload
                ?: throw IllegalArgumentException("Payload is not present and no external payload is supplied.")

        return SigStructure(
            sigContext = SigContext.Signature1,
            bodyProtected = headers?.protected,
            payload = payload,
            externalAad = externalAad,
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as COSESign1

        return headers == other.headers &&
            (payload?.contentEquals(other.payload) ?: (other.payload == null)) &&
            (signature?.contentEquals(other.signature) ?: (other.signature == null))
    }

    override fun hashCode(): Int {
        var result = headers?.hashCode() ?: 0
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + (signature?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(bytes: ByteArray): COSESign1 {
            try {
                val cborElement: CborElement = CborDecoder.decode(bytes)[0]
                return deserialize(cborElement)
            } catch (e: CborException) {
                throw CborException("Deserialization error.", e)
            }
        }

        fun deserialize(cborElement: CborElement): COSESign1 {
            if (MajorType.ARRAY != cborElement.majorType) {
                throw CborException(
                    "Deserialization error. Expected type: Array, Found: ${cborElement.majorType}",
                )
            }

            val coseSignDIs: List<CborElement> = (cborElement as CborArray).items()

            if (coseSignDIs.size != 4) {
                throw CborException("Deserialization error. Invalid array size. Expected size: , Found: ${coseSignDIs.size}")
            }

            val headers = Headers.deserialize(listOf(coseSignDIs[0], coseSignDIs[1]))

            val payload =
                if (coseSignDIs[2] === CborNull) {
                    null
                } else {
                    (coseSignDIs[2] as CborByteString).bytes
                }

            val signatureBS: CborByteString = coseSignDIs[3] as CborByteString
            val signature = signatureBS.bytes

            return COSESign1(headers, payload, signature)
        }
    }
}
