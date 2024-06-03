package dev.kryptonreborn.cose

import com.ionspin.kotlin.bignum.integer.BigInteger
import dev.kryptonreborn.cbor.model.CborNegativeInteger
import dev.kryptonreborn.cbor.model.CborUnicodeString
import dev.kryptonreborn.cbor.model.CborUnsignedInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class COSEUtilTest {
    @Test
    fun getIntOrTextTypeFromObject_forNumbers() {
        var di: CborUnsignedInteger = COSEUtil.getCborElementFromObject(4) as CborUnsignedInteger
        assertEquals(BigInteger(4), di.value)

        var ni: CborNegativeInteger = COSEUtil.getCborElementFromObject(-4) as CborNegativeInteger
        assertEquals(BigInteger(-4), ni.value)

        di = COSEUtil.getCborElementFromObject(500) as CborUnsignedInteger
        assertEquals(BigInteger(500), di.value)

        ni = COSEUtil.getCborElementFromObject(-500) as CborNegativeInteger
        assertEquals(BigInteger(-500), ni.value)

        di = COSEUtil.getCborElementFromObject(60000L) as CborUnsignedInteger
        assertEquals(BigInteger(60000L), di.value)

        ni = COSEUtil.getCborElementFromObject(-60000L) as CborNegativeInteger
        assertEquals(BigInteger(-60000L), ni.value)

        di = COSEUtil.getCborElementFromObject(BigInteger(3000)) as CborUnsignedInteger
        assertEquals(BigInteger(3000), di.value)

        ni = COSEUtil.getCborElementFromObject(BigInteger(-3000)) as CborNegativeInteger
        assertEquals(BigInteger(-3000), ni.value)
    }

    @Test
    fun getIntOrTextTypeFromObject_forString() {
        val textDI: CborUnicodeString = COSEUtil.getCborElementFromObject("hello") as CborUnicodeString
        assertEquals("hello", textDI.string)
    }

    @Test
    fun decodeNumberTypeFromCborElement() {
        val ui = CborUnsignedInteger(5000L)
        val res = COSEUtil.decodeFromCborElement(ui)
        assertEquals(5000L, res)
    }

    @Test
    fun decodeTextTypeFromCborElement() {
        val us = CborUnicodeString("Hello")
        val res = COSEUtil.decodeFromCborElement(us)
        assertEquals("Hello", res)
    }
}
