package dev.kryptonreborn.cose

import com.ionspin.kotlin.bignum.integer.BigInteger
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborMap
import dev.kryptonreborn.cbor.model.CborUnsignedInteger
import dev.kryptonreborn.cbor.model.MajorType
import dev.kryptonreborn.cose.COSEUtil.decodeFromCborElement
import dev.kryptonreborn.cose.COSEUtil.getCborElementFromObject

data class HeaderMap(
    val algorithmId: Any? = null,
    val criticality: List<Any> = listOf(),
    val contentType: Any? = null,
    val keyId: ByteArray? = null,
    val initVector: ByteArray? = null,
    val partialInitVector: ByteArray? = null,
    val counterSignature: List<COSESignature> = listOf(),
    val otherHeaders: MutableMap<Any, CborElement> = mutableMapOf(),
) : COSEItem {
    init {
        if (algorithmId != null) enforceFieldType(algorithmId)
        criticality.forEach { enforceFieldType(it) }
        if (contentType != null) enforceFieldType(contentType)
        otherHeaders.keys.forEach { enforceKeyType(it) }
    }

    override fun serialize(): CborElement {
        val cborMap = CborMap()

        algorithmId?.let { cborMap.put(CborUnsignedInteger(1), getCborElementFromObject(it)) }

        criticality.takeIf { it.isNotEmpty() }?.let {
            val valueArray = CborArray()
            it.forEach { crit -> valueArray.add(getCborElementFromObject(crit)) }
            cborMap.put(CborUnsignedInteger(2), valueArray)
        }

        contentType?.let { cborMap.put(CborUnsignedInteger(3), getCborElementFromObject(it)) }

        keyId?.let { cborMap.put(CborUnsignedInteger(4), CborByteString(it)) }

        initVector?.let { cborMap.put(CborUnsignedInteger(5), CborByteString(it)) }

        partialInitVector?.let { cborMap.put(CborUnsignedInteger(6), CborByteString(it)) }

        if (counterSignature.isNotEmpty()) {
            val values: List<CborElement> = counterSignature.map { it.serialize() }
            if (values.size == 1) {
                cborMap.put(CborUnsignedInteger(7), values[0])
            } else {
                val valueArray = CborArray()
                values.forEach { dataItem -> valueArray.add(dataItem) }
                cborMap.put(CborUnsignedInteger(7), valueArray)
            }
        }

        // Other headers
        otherHeaders.forEach { (key, value) ->
            cborMap.put(getCborElementFromObject(key), value)
        }

        return cborMap
    }

    companion object {
        fun deserialize(cborElement: CborElement): HeaderMap {
            if (cborElement.majorType != MajorType.MAP) {
                throw CborException("Deserialization error. Expected type: Map, Found: ${cborElement.majorType}")
            }

            val cborMap = cborElement as CborMap
            var algorithmId: Any? = null
            var criticality: MutableList<Any> = mutableListOf()
            var contentType: Any? = null
            var keyId: ByteArray? = null
            var initVector: ByteArray? = null
            var partialInitVector: ByteArray? = null
            var counterSignature: MutableList<COSESignature> = mutableListOf()
            val otherHeaders: LinkedHashMap<Any, CborElement> = LinkedHashMap()

            cborMap.keys().forEach { keyDI ->
                val valueDI = cborMap.get(keyDI)!!
                when (keyDI) {
                    CborUnsignedInteger(1) -> algorithmId = decodeFromCborElement(valueDI)
                    CborUnsignedInteger(2) -> {
                        if (valueDI.majorType == MajorType.ARRAY) {
                            criticality =
                                (valueDI as CborArray).items()
                                    .mapNotNull { decodeFromCborElement(it) }
                                    .toMutableList()
                        }
                    }

                    CborUnsignedInteger(3) -> contentType = decodeFromCborElement(valueDI)
                    CborUnsignedInteger(4) -> keyId = (valueDI as CborByteString).bytes
                    CborUnsignedInteger(5) -> initVector = (valueDI as CborByteString).bytes
                    CborUnsignedInteger(6) -> partialInitVector = (valueDI as CborByteString).bytes
                    CborUnsignedInteger(7) -> {
                        if (valueDI.majorType == MajorType.ARRAY) {
                            val counterSigArray = valueDI as CborArray
                            val counterSigDIs = counterSigArray.items()
                            if (counterSigDIs.isNotEmpty() && counterSigDIs[0].majorType == MajorType.ARRAY) {
                                counterSignature =
                                    counterSigDIs
                                        .map { COSESignature.deserialize(it) }
                                        .toMutableList()
                            } else {
                                counterSignature.add(COSESignature.deserialize(counterSigArray))
                            }
                        }
                    }

                    else -> {
                        otherHeaders[decodeFromCborElement(keyDI)!!] = valueDI
                    }
                }
            }

            return HeaderMap(
                algorithmId = algorithmId,
                criticality = criticality,
                contentType = contentType,
                keyId = keyId,
                initVector = initVector,
                counterSignature = counterSignature,
                partialInitVector = partialInitVector,
                otherHeaders = otherHeaders,
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HeaderMap) return false

        return algorithmId == other.algorithmId &&
            criticality == other.criticality &&
            contentType == other.contentType &&
            keyId?.contentEquals(other.keyId) ?: (other.keyId == null) &&
            initVector?.contentEquals(other.initVector) ?: (other.initVector == null) &&
            partialInitVector?.contentEquals(other.partialInitVector) ?: (other.partialInitVector == null) &&
            counterSignature == other.counterSignature &&
            otherHeaders == other.otherHeaders
    }

    override fun hashCode(): Int {
        var result = algorithmId?.hashCode() ?: 0
        result = 31 * result + criticality.hashCode()
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (initVector?.contentHashCode() ?: 0)
        result = 31 * result + (partialInitVector?.contentHashCode() ?: 0)
        result = 31 * result + counterSignature.hashCode()
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
            throw IllegalArgumentException("Field type must be either Long or String")
        }
    }
}
