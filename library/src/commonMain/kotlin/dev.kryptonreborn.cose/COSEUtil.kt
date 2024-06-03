package dev.kryptonreborn.cose

import com.ionspin.kotlin.bignum.integer.BigInteger
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNegativeInteger
import dev.kryptonreborn.cbor.model.CborUnicodeString
import dev.kryptonreborn.cbor.model.CborUnsignedInteger
import dev.kryptonreborn.cbor.model.MajorType

internal object COSEUtil {
    /**
     * Convert a Long / Integer / BigInteger / String / byte[] to CborElement
     *
     * @param value
     * @return CborElement
     */
    fun getCborElementFromObject(value: Any): CborElement {
        when (value) {
            is Long -> {
                return if (value >= 0L) {
                    CborUnsignedInteger(value)
                } else {
                    CborNegativeInteger(value)
                }
            }

            is Int -> {
                return if (value >= 0) {
                    CborUnsignedInteger(value.toLong())
                } else {
                    CborNegativeInteger(value.toLong())
                }
            }

            is BigInteger -> {
                return if (value >= BigInteger.ZERO) {
                    CborUnsignedInteger(value)
                } else {
                    CborNegativeInteger(value)
                }
            }

            is String -> {
                return CborUnicodeString(value)
            }

            is ByteArray -> {
                return CborByteString(value)
            }

            else -> {
                throw CborException("Serialization error. Expected type: long / Integer / BigInteger / String / byte[], found: $value")
            }
        }
    }

    /**
     * Convert a CborElement to BigInt or String or byte[]
     *
     * @param cborElement
     * @return Long or String value
     */
    fun decodeFromCborElement(cborElement: CborElement?): Any? {
        return when (cborElement?.majorType) {
            null -> null
            MajorType.UNSIGNED_INTEGER -> (cborElement as CborUnsignedInteger).value.longValue()
            MajorType.NEGATIVE_INTEGER -> (cborElement as CborNegativeInteger).value.longValue()
            MajorType.UNICODE_STRING -> (cborElement as CborUnicodeString).string
            MajorType.BYTE_STRING -> (cborElement as CborByteString).bytes
            else -> throw CborException("Deserialization error: Unexpected data type: ${cborElement.majorType}")
        }
    }
}
