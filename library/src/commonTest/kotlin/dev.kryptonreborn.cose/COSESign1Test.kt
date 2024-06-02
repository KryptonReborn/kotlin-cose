package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborUnicodeString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@ExperimentalStdlibApi
class COSESign1Test : COSEBaseTest() {
    @Test
    fun serDesCoseSign1() {
        val hm =
            HeaderMap(
                contentType = -1000L,
            )

        val headers =
            Headers(
                protected = ProtectedHeaderMap(ByteArray(0)),
                unprotected = hm,
            )

        val payload = getBytes(64, 39)
        val signature = byteArrayOf(1, 2, 100)

        val coseSign1 =
            COSESign1(
                headers = headers,
                payload = payload,
                signature = signature,
            )

        val coseSignNoPayload =
            COSESign1(
                headers = headers,
                payload = null,
                signature = signature,
            )

        val expectedPayloadSerBytes =
            "8440a1033903e7582740404040404040404040404040404040404040404040404040404040404040404040404040404043010264"
        val expectedNoPayloadSerBytes = "8440a1033903e7f643010264"

        deserializationTest(coseSign1, expectedPayloadSerBytes)
        deserializationTest(coseSignNoPayload, expectedNoPayloadSerBytes)
    }

    @Test
    fun testSignedData() {
        // Payload = "hello"
        val coseSignMsgInHex =
            "845869a30127045820674d11e432450118d70ea78673d5e31d5cc1aec63de0ff6284784876544be3406761646472657373583" +
                "901d2eb831c6cad4aba700eb35f86966fbeff19d077954430e32ce65e8da79a3abe84f4ce817fad066acc1435be2ffc6bd" +
                "7dce2ec1cc6cca6cba166686173686564f44568656c6c6f5840a3b5acd99df5f3b5e4449c5a116078e9c0fcfc126a4d4e2" +
                "f6a9565f40b0c77474cafd89845e768fae3f6eec0df4575fcfe7094672c8c02169d744b415c617609"
        val coseSign1: COSESign1 = COSESign1.deserialize(coseSignMsgInHex.hexToByteArray())

        val sigStructure = coseSign1.signedData(null, null)

        assertEquals(sigStructure.sigContext, SigContext.Signature1)
        assertEquals(sigStructure.bodyProtected, coseSign1.headers?.protected)
        assertEquals(sigStructure.externalAad, null)
        assertContentEquals(sigStructure.payload, "hello".encodeToByteArray())
        assertEquals(sigStructure.signProtected, null)
    }

    @Test
    fun testSignedData_noparams() {
        // Payload = "hello"
        val coseSignMsgInHex =
            "845869a30127045820674d11e432450118d70ea78673d5e31d5cc1aec63de0ff6284784876544be3406761646472657373583901d" +
                "2eb831c6cad4aba700eb35f86966fbeff19d077954430e32ce65e8da79a3abe84f4ce817fad066acc1435be2ffc6bd7dc" +
                "e2ec1cc6cca6cba166686173686564f44568656c6c6f5840a3b5acd99df5f3b5e4449c5a116078e9c0fcfc126a4d4e2f" +
                "6a9565f40b0c77474cafd89845e768fae3f6eec0df4575fcfe7094672c8c02169d744b415c617609"
        val coseSign1: COSESign1 = COSESign1.deserialize(coseSignMsgInHex.hexToByteArray())

        val sigStructure = coseSign1.signedData()

        assertEquals(sigStructure.sigContext, SigContext.Signature1)
        assertEquals(sigStructure.bodyProtected, coseSign1.headers?.protected)
        assertEquals(sigStructure.externalAad, null)
        assertContentEquals(sigStructure.payload, "hello".encodeToByteArray())
        assertEquals(sigStructure.signProtected, null)
    }

    @Test
    fun testSignedData_nopayloadAndnoextpayload_throwsException() {
        val coseSign1 =
            COSESign1(
                headers =
                    Headers(
                        protected =
                            ProtectedHeaderMap(
                                HeaderMap(
                                    otherHeaders =
                                        mutableMapOf<Any, CborElement>().apply {
                                            put(
                                                "key1",
                                                CborUnicodeString("value1"),
                                            )
                                        },
                                ),
                            ),
                    ),
                signature = getBytes(1, 64),
            )

        assertFailsWith<IllegalArgumentException> { coseSign1.signedData(null, null) }
    }

    private fun deserializationTest(
        hm: COSESign1,
        expectedHex: String? = null,
    ): COSESign1 {
        val serializeByte1 = hm.serializeAsBytes()
        val serializeByte2: ByteArray
        val deCoseSign1: COSESign1 = COSESign1.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = deCoseSign1.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return deCoseSign1
    }
}
