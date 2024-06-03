package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class PasswordEncryptionTest : COSEBaseTest() {
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
            COSEEncrypt0(
                headers = headers,
                ciphertext = "This is a msg".encodeToByteArray(),
            )

        val pwdEncryption = PasswordEncryption(coseEncrypt)

        deserializationTest(pwdEncryption)
    }

    private fun deserializationTest(
        pke: PasswordEncryption,
        expectedHex: String? = null,
    ): PasswordEncryption {
        val serializeByte1 = pke.serializeAsBytes()
        val serializeByte2: ByteArray
        val dePEnc: PasswordEncryption = PasswordEncryption.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = dePEnc.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return dePEnc
    }
}
