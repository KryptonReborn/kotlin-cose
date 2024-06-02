package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborEncoder
import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborElement
import kotlinx.io.Buffer
import kotlinx.io.readByteArray

interface COSEItem {
    fun serializeAsBytes(): ByteArray {
        val cborElement: CborElement = serialize()

        try {
            val sourceOut = Buffer()
            CborEncoder(sourceOut).apply { canonical = false }.encode(cborElement)
            return sourceOut.readByteArray()
        } catch (e: CborException) {
            throw RuntimeException("Cbor serialization error", e)
        }
    }

    fun serialize(): CborElement
}
