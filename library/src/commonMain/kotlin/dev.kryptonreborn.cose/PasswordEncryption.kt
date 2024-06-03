package dev.kryptonreborn.cose

import dev.kryptonreborn.cbor.CborException
import dev.kryptonreborn.cbor.model.CborArray
import dev.kryptonreborn.cbor.model.CborElement
import dev.kryptonreborn.cbor.model.CborTag

data class PasswordEncryption(val coseEncrypt0: COSEEncrypt0) : COSEItem {
    override fun serialize(): CborElement {
        val coseEncryptArr: CborArray = coseEncrypt0.serialize()
        coseEncryptArr.tag = CborTag(16)

        return coseEncryptArr
    }

    companion object {
        fun deserialize(cborElement: CborElement): PasswordEncryption {
            val tag: CborTag? = cborElement.tag
            if (tag == null || tag.value != 16L) throw CborException("Cbor deserialization error. Invalid or null tag. Expected value: 16")

            return PasswordEncryption(COSEEncrypt0.deserialize(cborElement as CborArray))
        }
    }
}
