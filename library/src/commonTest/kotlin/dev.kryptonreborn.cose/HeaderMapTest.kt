package dev.kryptonreborn.cose

import com.ionspin.kotlin.bignum.integer.BigInteger
import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborNull
import dev.kryptonreborn.cbor.model.CborUnicodeString
import dev.kryptonreborn.cbor.model.CborUnsignedInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class HeaderMapTest : COSEBaseTest() {
    @Test
    fun emptyOrSerializedMap() {
        val hm =
            HeaderMap(
                algorithmId = 199L,
                partialInitVector = byteArrayOf(0, 1, 2),
            )

        val deHm = deserializationTest(hm)

        assertEquals(hm.algorithmId, deHm.algorithmId)
        assertContentEquals(hm.partialInitVector, deHm.partialInitVector)
    }

    @Test
    fun emptyMap() {
        val hm = HeaderMap()

        deserializationTest(hm)
    }

    @Test
    fun serDesHeaderMap() {
        val hm =
            HeaderMap(
                keyId = getBytes(7, 7),
                contentType = -9L,
            )

        val coseSignature =
            COSESignature(
                headers =
                    Headers(
                        protected = ProtectedHeaderMap(hm),
                        unprotected = hm,
                    ),
                signature = getBytes(87, 74),
            )

        val otherHeaderMap: LinkedHashMap<Any, CborElement> = LinkedHashMap()
        otherHeaderMap["i am a string key"] = CborUnicodeString("also a string")

        val headerMap =
            HeaderMap(
                algorithmId = 0L,
                criticality = mutableListOf(-166L, "dsfdsf8353jh5  fsdfd!%&#%3j"),
                contentType = "content-type",
                keyId = getBytes(34, 32),
                initVector = getBytes(97, 16),
                partialInitVector = getBytes(5, 13),
                counterSignature = mutableListOf(coseSignature),
                otherHeaders = otherHeaderMap,
            )

        val serializedHex: String = headerMap.serializeAsBytes().toHexString()
        val expectedHex =
            "a80100028238a5781b647366647366383335336a6835202066736466642125262325336a036c636f6e74656e742d747970650458" +
                "20222222222222222222222222222222222222222222222222222222222222222205506161616161616161616161616161" +
                "6161064d0505050505050505050505050507834ca20328044707070707070707a20328044707070707070707584a575757" +
                "57575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757" +
                "57575757575757575757575757575757575757575757716920616d206120737472696e67206b65796d616c736f20612073" +
                "7472696e67"

        assertEquals(expectedHex, serializedHex)

        deserializationTest(headerMap)
    }

    @Test
    @Throws(CborException::class)
    fun serDesHeaderMap2() {
        val hm =
            HeaderMap(
                keyId = getBytes(7, 7),
                contentType = -9L,
            )

        val coseSignature =
            COSESignature(
                headers =
                    Headers(
                        protected = ProtectedHeaderMap(hm),
                        unprotected = hm,
                    ),
                signature = getBytes(87, 74),
            )

        // additional header item

        val nullValue = CborArray()
        nullValue.add(CborUnsignedInteger(3))
        nullValue.add(CborNull)

        val headerMap =
            HeaderMap(
                algorithmId = 0L,
                criticality = mutableListOf(-166L, "dsfdsf8353jh5  fsdfd!%&#%3j"),
                contentType = "content-type",
                keyId = getBytes(34, 32),
                initVector = getBytes(97, 16),
                partialInitVector = getBytes(5, 13),
                counterSignature = mutableListOf(coseSignature),
                otherHeaders =
                    mutableMapOf<Any, CborElement>().apply {
                        put("i am a string key", CborUnicodeString("also a string"))
                        put(-6L, nullValue)
                    },
            )

        val serializedHex: String = headerMap.serializeAsBytes().toHexString()
        val expectedHex =
            "a90100028238a5781b647366647366383335336a6835202066736466642125262325336a036c636f6e74656e742d74797065045820" +
                "22222222222222222222222222222222222222222222222222222222222222220550616161616161616161616161616161" +
                "61064d0505050505050505050505050507834ca20328044707070707070707a20328044707070707070707584a57575757" +
                "57575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757" +
                "575757575757575757575757575757575757575757716920616d206120737472696e67206b65796d616c736f2061207374" +
                "72696e67258203f6"
        assertEquals(expectedHex, serializedHex)

        deserializationTest(headerMap)
    }

    @Test
    fun serDesHeaderMap_multipleSignatures() {
        val hm =
            HeaderMap(
                keyId = getBytes(7, 7),
                contentType = -9L,
                otherHeaders =
                    linkedMapOf(
                        BigInteger(99999999L) to CborUnicodeString("Value1"),
                        200L to CborUnsignedInteger(30000),
                    ),
            )

        val headers =
            Headers(
                protected = ProtectedHeaderMap(hm),
                unprotected = hm,
            )

        val coseSignature1 =
            COSESignature(
                headers = headers,
                signature = getBytes(87, 74),
            )

        val coseSignature2 =
            COSESignature(
                headers = headers,
                signature = getBytes(22, 64),
            )

        val otherHeaderMap: LinkedHashMap<Any, CborElement> = LinkedHashMap()
        otherHeaderMap["i am a string key"] = CborUnicodeString("also a string")

        val headerMap =
            HeaderMap(
                algorithmId = 0L,
                criticality = mutableListOf(-166L, "dsfdsf8353jh5  fsdfd!%&#%3j"),
                contentType = "content-type",
                keyId = getBytes(34, 32),
                initVector = getBytes(97, 16),
                partialInitVector = getBytes(5, 13),
                counterSignature = mutableListOf(coseSignature1, coseSignature2),
                otherHeaders = otherHeaderMap,
            )

        deserializationTest(headerMap)
    }

    private fun deserializationTest(hm: HeaderMap): HeaderMap {
        val serializeByte1 = hm.serializeAsBytes()
        val serializeByte2: ByteArray
        val deHM: HeaderMap = HeaderMap.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = deHM.serializeAsBytes()

        assertContentEquals(serializeByte2, serializeByte1)

        return deHM
    }
}
