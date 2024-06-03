package dev.kryptonreborn.cose

open class COSEBaseTest {
    protected fun getBytes(
        b: Int,
        noOf: Int,
    ): ByteArray {
        val result = ByteArray(noOf)

        for (i in 0 until noOf) {
            result[i] = b.toByte()
        }

        return result
    }
}
