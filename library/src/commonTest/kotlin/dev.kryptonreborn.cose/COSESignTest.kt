package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class COSESignTest : COSEBaseTest() {
    @Test
    fun serDesCoseSign() {
        val hm = HeaderMap(contentType = -1000L)
        val protectedHeader = ProtectedHeaderMap(ByteArray(0))
        val headers = Headers(protected = protectedHeader, unprotected = hm)
        val payload = getBytes(64, 39)
        val signature1 = byteArrayOf(1, 2, 100)
        val coseSignature1 = COSESignature(signature = signature1, headers = headers)
        val signature2 = byteArrayOf(3, 2, 100, 101)
        val coseSignature2 = COSESignature(signature = signature2, headers = headers)

        val coseSign =
            COSESign(
                headers = headers,
                payload = payload,
                signatures = mutableListOf(coseSignature1, coseSignature2),
            )

        val deCoseSign = deserializationTest(coseSign)

        // Random fields check
        assertEquals(-1000L, deCoseSign.headers?.unprotected?.contentType)
        assertEquals(-1000L, deCoseSign.signatures[0].headers?.unprotected?.contentType)
        assertEquals(-1000L, deCoseSign.signatures[1].headers?.unprotected?.contentType)
    }

    private fun deserializationTest(
        hm: COSESign,
        expectedHex: String? = null,
    ): COSESign {
        val serializeByte1 = hm.serializeAsBytes()
        val serializeByte2: ByteArray
        val deCoseSign: COSESign = COSESign.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = deCoseSign.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return deCoseSign
    }
}
