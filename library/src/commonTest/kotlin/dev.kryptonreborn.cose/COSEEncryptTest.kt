package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.model.CborArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class COSEEncryptTest : COSEBaseTest() {
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
            COSEEncrypt(
                headers = headers,
                ciphertext = "This is a msg".encodeToByteArray(),
                recipients =
                    mutableListOf(
                        COSERecipient(
                            headers = headers,
                            ciphertext = "Recipient1 msg".encodeToByteArray(),
                        ),
                        COSERecipient(
                            headers = headers,
                            ciphertext = "Recipient2 msg".encodeToByteArray(),
                        ),
                    ),
            )

        val deCOSEEnc = deserializationTest(coseEncrypt)

        assertEquals(2, deCOSEEnc.recipients.size)
        assertEquals(coseEncrypt.recipients[0], deCOSEEnc.recipients[0])
        assertEquals(coseEncrypt.recipients[1], deCOSEEnc.recipients[1])
    }

    private fun deserializationTest(cosEnc: COSEEncrypt): COSEEncrypt {
        val serializeByte1 = cosEnc.serializeAsBytes()
        val serializeByte2: ByteArray
        val deCOSEncrypt: COSEEncrypt = COSEEncrypt.deserialize(CborDecoder.decode(serializeByte1)[0] as CborArray)
        serializeByte2 = deCOSEncrypt.serializeAsBytes()

        assertContentEquals(serializeByte2, serializeByte1)

        return deCOSEncrypt
    }
}
