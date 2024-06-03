package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class COSESignatureTest : COSEBaseTest() {
    @Test
    fun serDesCOSESignature() {
        val coseSignature =
            COSESignature(
                headers =
                    Headers(
                        protected = ProtectedHeaderMap(),
                        unprotected =
                            HeaderMap(
                                criticality = mutableListOf(8L),
                                algorithmId = 3L,
                            ),
                    ),
                signature = getBytes(5, 64),
            )

        deserializationTest(coseSignature)
    }

    private fun deserializationTest(
        hm: COSESignature,
        expectedHex: String? = null,
    ): COSESignature {
        val serializeByte1 = hm.serializeAsBytes()
        val serializeByte2: ByteArray
        val coseSignature: COSESignature = COSESignature.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = coseSignature.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return coseSignature
    }
}
