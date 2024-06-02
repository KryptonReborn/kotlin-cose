package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class PubKeyEncryptionTest : COSEBaseTest() {
    @Test
    fun serDesPubKeyEncryption() {
        val hm =
            HeaderMap(
                keyId = getBytes(7, 7),
                contentType = -9L,
            )

        val headers =
            Headers(
                protected = ProtectedHeaderMap(),
                unprotected = hm,
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

        val pubKeyEncryption = PubKeyEncryption(coseEncrypt)

        deserializationTest(pubKeyEncryption)
    }

    private fun deserializationTest(
        pke: PubKeyEncryption,
        expectedHex: String? = null,
    ): PubKeyEncryption {
        val serializeByte1 = pke.serializeAsBytes()
        val serializeByte2: ByteArray
        val dePKE: PubKeyEncryption = PubKeyEncryption.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = dePKE.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return dePKE
    }
}
