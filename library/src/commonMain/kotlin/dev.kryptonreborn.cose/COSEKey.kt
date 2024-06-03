package dev.kryptonreborn.cose

import com.ionspin.kotlin.bignum.integer.BigInteger
import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborMap
import dev.kryptonreborn.cbor.model.CborUnsignedInteger
import dev.kryptonreborn.cbor.model.MajorType
import dev.kryptonreborn.cose.COSEUtil.decodeFromCborElement
import dev.kryptonreborn.cose.COSEUtil.getCborElementFromObject

data class COSEKey(
    val keyType: Any? = null,
    val keyId: ByteArray? = null,
    val algorithmId: Any? = null,
    val keyOps: List<Any> = listOf(),
    val baseInitVector: ByteArray? = null,
    val otherHeaders: MutableMap<Any, CborElement> = mutableMapOf(),
) : COSEItem {
    init {
        if (algorithmId != null) enforceFieldType(algorithmId)
        if (keyType != null) enforceFieldType(keyType)
        keyOps.forEach { enforceFieldType(it) }
        otherHeaders.keys.forEach { enforceKeyType(it) }
    }

    override fun serialize(): CborMap {
        val map = CborMap()

        keyType?.let { map.put(CborUnsignedInteger(1), getCborElementFromObject(it)) }
        keyId?.let { map.put(CborUnsignedInteger(2), CborByteString(it)) }
        algorithmId?.let { map.put(CborUnsignedInteger(3), getCborElementFromObject(it)) }
        keyOps.takeIf { it.isNotEmpty() }?.let {
            val valueArray = CborArray()
            it.forEach { crit -> valueArray.add(getCborElementFromObject(crit)) }
            map.put(CborUnsignedInteger(4), valueArray)
        }
        baseInitVector?.let { map.put(CborUnsignedInteger(5), CborByteString(it)) }

        // Other headers
        otherHeaders.forEach { (key, value) -> map.put(getCborElementFromObject(key), value) }

        return map
    }

    companion object {
        fun deserialize(bytes: ByteArray): COSEKey {
            return try {
                val cborElement = CborDecoder.decode(bytes)[0]
                deserialize(cborElement)
            } catch (e: CborException) {
                throw CborException("Deserialization error.", e)
            }
        }

        fun deserialize(cborElement: CborElement): COSEKey {
            if (cborElement.majorType != MajorType.MAP) {
                throw CborException("Deserialization error. Expected type: Map, Found: ${cborElement.majorType}")
            }

            val map = cborElement as CborMap
            var keyType: Any? = null
            var keyId: ByteArray? = null
            var algorithmId: Any? = null
            var keyOps: MutableList<Any> = mutableListOf()
            var baseInitVector: ByteArray? = null
            val otherHeaders: LinkedHashMap<Any, CborElement> = LinkedHashMap()

            map.keys().forEach { keyDI ->
                val valueDI = map.get(keyDI)!!
                when (keyDI) {
                    CborUnsignedInteger(1) -> keyType = decodeFromCborElement(valueDI)
                    CborUnsignedInteger(2) -> keyId = (valueDI as CborByteString).bytes
                    CborUnsignedInteger(3) -> algorithmId = decodeFromCborElement(valueDI)

                    CborUnsignedInteger(4) -> {
                        if (valueDI.majorType == MajorType.ARRAY) {
                            keyOps =
                                (valueDI as CborArray).items()
                                    .mapNotNull { decodeFromCborElement(it) }.toMutableList()
                        }
                    }

                    CborUnsignedInteger(5) -> baseInitVector = (valueDI as CborByteString).bytes
                    else -> otherHeaders[decodeFromCborElement(keyDI)!!] = valueDI
                }
            }

            return COSEKey(
                keyType = keyType,
                keyId = keyId,
                algorithmId = algorithmId,
                keyOps = keyOps,
                baseInitVector = baseInitVector,
                otherHeaders = otherHeaders,
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as COSEKey

        return keyType == other.keyType &&
            (keyId?.contentEquals(other.keyId) ?: (other.keyId == null)) &&
            algorithmId == other.algorithmId &&
            keyOps == other.keyOps &&
            (baseInitVector?.contentEquals(other.baseInitVector) ?: (other.baseInitVector == null)) &&
            otherHeaders == other.otherHeaders
    }

    override fun hashCode(): Int {
        var result = keyType?.hashCode() ?: 0
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (algorithmId?.hashCode() ?: 0)
        result = 31 * result + keyOps.hashCode()
        result = 31 * result + (baseInitVector?.contentHashCode() ?: 0)
        result = 31 * result + otherHeaders.hashCode()
        return result
    }

    private fun enforceKeyType(value: Any) {
        if (value !is BigInteger && value !is Long && value !is String) {
            throw IllegalArgumentException("Key type must be BigInteger, Long, or String")
        }
    }

    private fun enforceFieldType(value: Any) {
        if (value !is Long && value !is String) {
            throw IllegalArgumentException("Header type must be either Long or String")
        }
    }
}
