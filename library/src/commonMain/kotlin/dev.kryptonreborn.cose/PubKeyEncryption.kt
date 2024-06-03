package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborTag

data class PubKeyEncryption(private val coseEncrypt: COSEEncrypt) : COSEItem {
    override fun serialize(): CborElement {
        val coseEncryptArr: CborArray = coseEncrypt.serialize()
        coseEncryptArr.tag = CborTag(96)

        return coseEncryptArr
    }

    companion object {
        fun deserialize(cborElement: CborElement): PubKeyEncryption {
            val tag: CborTag? = cborElement.tag
            if (tag == null || tag.value != 96L) throw CborException("Cbor deserialization error. Invalid or null tag. Expected value: 96")

            return PubKeyEncryption(COSEEncrypt.deserialize(cborElement as CborArray))
        }
    }
}
