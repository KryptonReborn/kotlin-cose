package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborUnicodeString
import dev.kryptonreborn.cbor.model.MajorType

data class SigStructure(
    val bodyProtected: ProtectedHeaderMap? = null,
    val signProtected: ProtectedHeaderMap? = null,
    val sigContext: SigContext,
    val externalAad: ByteArray? = null,
    val payload: ByteArray? = null,
) : COSEItem {
    override fun serialize(): CborElement {
        val sigStructArray = CborArray()

        sigStructArray.add(CborUnicodeString(sigContext.toString()))

        sigStructArray.add(bodyProtected?.serialize() ?: CborByteString(ByteArray(0)))

        signProtected?.let { sigStructArray.add(it.serialize()) }

        sigStructArray.add(CborByteString(externalAad ?: ByteArray(0)))
        sigStructArray.add(CborByteString(payload ?: ByteArray(0)))

        return sigStructArray
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SigStructure

        return bodyProtected == other.bodyProtected &&
            signProtected == other.signProtected &&
            sigContext == other.sigContext &&
            (externalAad?.contentEquals(other.externalAad) ?: (other.externalAad == null)) &&
            (payload?.contentEquals(other.payload) ?: (other.payload == null))
    }

    override fun hashCode(): Int {
        var result = bodyProtected?.hashCode() ?: 0
        result = 31 * result + (signProtected?.hashCode() ?: 0)
        result = 31 * result + sigContext.hashCode()
        result = 31 * result + (externalAad?.contentHashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(cborElement: CborElement): SigStructure {
            if (MajorType.ARRAY != cborElement.majorType) {
                throw CborException(
                    "Cbor deserialization error. Expected Array. Found: ${cborElement.majorType}",
                )
            }

            val sigStructDIs: List<CborElement> = (cborElement as CborArray).items()

            if (sigStructDIs.size != 4 && sigStructDIs.size != 5) {
                throw CborException(
                    "Cbor de-serialization error. Expected no of item in array: 4 or 5, Found: ${sigStructDIs.size}",
                )
            }

            var index = 0

            return SigStructure(
                sigContext = SigContext.valueOf((sigStructDIs[index++] as CborUnicodeString).string!!),
                bodyProtected = ProtectedHeaderMap.deserialize(sigStructDIs[index++]),
                signProtected = ProtectedHeaderMap.deserialize(sigStructDIs[index++]).takeIf { sigStructDIs.size == 5 },
                externalAad = (sigStructDIs[index++] as CborByteString).bytes,
                payload = (sigStructDIs[index] as CborByteString).bytes,
            )
        }
    }
}
