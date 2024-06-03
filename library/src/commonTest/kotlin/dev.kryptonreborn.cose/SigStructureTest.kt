package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborDecoder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class SigStructureTest : COSEBaseTest() {
    @Test
    fun serDesSigStructureSignature() {
        val sigStructure =
            SigStructure(
                sigContext = SigContext.Signature,
                bodyProtected = ProtectedHeaderMap(),
                signProtected = ProtectedHeaderMap(),
                externalAad = byteArrayOf(8, 9, 100),
                payload = getBytes(73, 23),
            )

        val expectedSerHex = "85695369676e6174757265404043080964574949494949494949494949494949494949494949494949"
        val deSigStruct = deserializationTest(sigStructure, expectedSerHex)

        assertEquals(SigContext.Signature, deSigStruct.sigContext)
    }

    private fun deserializationTest(
        hm: SigStructure,
        expectedHex: String? = null,
    ): SigStructure {
        val serializeByte1 = hm.serializeAsBytes()
        val serializeByte2: ByteArray
        val sigStructure: SigStructure = SigStructure.deserialize(CborDecoder.decode(serializeByte1)[0])
        serializeByte2 = sigStructure.serializeAsBytes()

        assertContentEquals(serializeByte1, serializeByte2)

        if (expectedHex != null) {
            assertEquals(serializeByte1.toHexString(), expectedHex)
        }

        return sigStructure
    }
}
