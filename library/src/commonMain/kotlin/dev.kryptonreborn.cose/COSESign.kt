package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborEncoder
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNull
import dev.kryptonreborn.cbor.model.MajorType

data class COSESign(
    val headers: Headers? = null,
    val payload: ByteArray? = null,
    val signatures: List<COSESignature> = listOf(),
) : COSEItem {
    override fun serialize(): CborArray {
        val cosignArray = CborArray()
        headers?.serialize()?.forEach { headerItem -> cosignArray.add(headerItem!!) }

        if (payload != null && payload.isNotEmpty()) {
            cosignArray.add(CborByteString(payload))
        } else {
            cosignArray.add(CborNull)
        }

        if (signatures.isNotEmpty()) {
            val signatureArray = CborArray()
            signatures.forEach { signature -> signatureArray.add(signature.serialize()) }

            cosignArray.add(signatureArray)
        } else {
            throw CborException("Cbor serialization failed. One or more signatures required")
        }

        return cosignArray
    }

    override fun serializeAsBytes(): ByteArray {
        return try {
            CborEncoder.encodeToBytes(serialize())
        } catch (e: CborException) {
            throw CborException("Cbor serialization error", e)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as COSESign

        return headers == other.headers &&
            (payload?.contentEquals(other.payload) ?: (other.payload == null)) &&
            signatures == other.signatures
    }

    override fun hashCode(): Int {
        var result = headers?.hashCode() ?: 0
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + signatures.hashCode()
        return result
    }

    companion object {
        fun deserialize(cborElement: CborElement): COSESign {
            if (cborElement.majorType != MajorType.ARRAY) {
                throw CborException("De-serialization error. Expected type: Array, Found: ${cborElement.majorType}")
            }

            val coseSignDIs = (cborElement as CborArray).items()

            if (coseSignDIs.size != 4) {
                throw CborException("Deserialization error. Invalid array size. Expected size: 4, Found: ${coseSignDIs.size}")
            }

            val headers = Headers.deserialize(listOf(coseSignDIs[0], coseSignDIs[1]))
            val payload =
                if (coseSignDIs[2] is CborByteString) {
                    (coseSignDIs[2] as CborByteString).bytes
                } else {
                    null
                }

            // Signatures
            val signatureDIs = (coseSignDIs[3] as CborArray).items()
            val signatures = signatureDIs.map { signatureDI -> COSESignature.deserialize(signatureDI) }.toMutableList()

            return COSESign(
                headers = headers,
                payload = payload,
                signatures = signatures,
            )
        }
    }
}
