package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.model.CborArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class COSEEncrypt0Test : COSEBaseTest() {
    @Test
    fun serDesCOSEEncrypt() {
        val headerMap =
            HeaderMap(
                keyId = getBytes(7, 7),
                contentType = -9L,
            )

        val headers =
            Headers(
                protected = ProtectedHeaderMap(),
                unprotected = headerMap,
            )

        val coseEncrypt =
            COSEEncrypt0(
                headers = headers,
                ciphertext = "This is a msg".encodeToByteArray(),
            )

        val deCOSEEnc = deserializationTest(coseEncrypt)

        assertEquals(coseEncrypt, deCOSEEnc)
    }

    private fun deserializationTest(cosEnc: COSEEncrypt0): COSEEncrypt0 {
        val serializeByte1 = cosEnc.serializeAsBytes()
        val serializeByte2: ByteArray
        val deCOSEncrypt: COSEEncrypt0 = COSEEncrypt0.deserialize(CborDecoder.decode(serializeByte1)[0] as CborArray)
        serializeByte2 = deCOSEncrypt.serializeAsBytes()

        assertContentEquals(serializeByte2, serializeByte1)

        return deCOSEncrypt
    }
}
