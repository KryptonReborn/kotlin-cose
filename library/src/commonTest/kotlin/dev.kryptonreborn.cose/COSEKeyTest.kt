package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborByteString
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborUnicodeString
import dev.kryptonreborn.cbor.model.CborUnsignedInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class COSEKeyTest : COSEBaseTest() {
    @Test
    fun serDesCOSEKey() {
        val coseKey =
            COSEKey(
                keyType = "key type 1",
                keyId = byteArrayOf(1, 2, 5, 10, 20, 40, 50),
                algorithmId = -10L,
                keyOps = mutableListOf("dfdsfds", -130L),
                baseInitVector = getBytes(0, 128),
            )

        val expectedHex =
            "a5016a6b65792074797065203102470102050a1428320329048267646664736664733881055880000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "00000000000000000000000000000000000"
        deserializationTest(coseKey, expectedHex)
    }

    @Test
    fun serDesCOSEKey_otherKey_overlap() {
        val coseKey =
            COSEKey(
                keyType = "key type 1",
                keyId = byteArrayOf(1, 2, 5, 10, 20, 40, 50),
                algorithmId = -10L,
                keyOps = mutableListOf("dfdsfds", -130L),
                baseInitVector = getBytes(0, 128),
            )

        val kty2: Long = 352
        val kid2 = getBytes(7, 23)
        val alg2 = "algorithm 2"
        val ops2: MutableList<Any> = mutableListOf()
        ops2.add("89583249384")
        val biv2 = byteArrayOf(10, 0, 5, 9, 50, 100, 30)

        val kty2Value: CborElement = CborUnsignedInteger(352)
        val kid2Value: CborElement = CborByteString(kid2.copyOf())
        val alg2Value: CborElement = CborUnicodeString("algorithm 2")
        val ops2Value = CborArray()
        ops2Value.add(CborUnicodeString("89583249384"))
        val biv2Value: CborElement = CborByteString(biv2.copyOf())

        val expectedHex =
            "a5016a6b65792074797065203102470102050a142832032904826764666473666473388105588000000000000000000000000000000" +
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "00000000000000000000000000000000"
        var deCoseKey = deserializationTest(coseKey, expectedHex)

        assertEquals(coseKey, deCoseKey)

        // overwrite some default headers
        coseKey.otherHeaders[1L] = kty2Value
        coseKey.otherHeaders[2L] = kid2Value
        coseKey.otherHeaders[3L] = alg2Value
        coseKey.otherHeaders[4L] = ops2Value
        coseKey.otherHeaders[5L] = biv2Value
        coseKey.otherHeaders["key1"] = CborUnicodeString("key1 value")
        coseKey.otherHeaders[-100L] = CborByteString(byteArrayOf(2, 3))

        deCoseKey = deserializationTest(coseKey)

        assertEquals(kty2, deCoseKey.keyType)
        assertContentEquals(kid2, deCoseKey.keyId)
        assertEquals(alg2, deCoseKey.algorithmId)
        assertEquals(ops2, deCoseKey.keyOps)
        assertContentEquals(biv2, deCoseKey.baseInitVector)
        assertEquals(CborUnicodeString("key1 value"), deCoseKey.otherHeaders["key1"])
        assertEquals(CborByteString(byteArrayOf(2, 3)), deCoseKey.otherHeaders[-100L])
    }

    private fun deserializationTest(
        coseKey: COSEKey,
        expectedHex: String? = null,
    ): COSEKey {
        val serializeByte1 = coseKey.serializeAsBytes()
        val serializeByte2: ByteArray
        val deCOSEKey: COSEKey = COSEKey.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = deCOSEKey.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return deCOSEKey
    }
}
