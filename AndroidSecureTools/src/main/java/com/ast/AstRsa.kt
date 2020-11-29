package com.ast

import com.ast.utils.RsaKeyLength

object AstRsa {

    init {
        System.loadLibrary("RsaConnector")
    }

    fun generateKeyPair(keyLength: RsaKeyLength) {
        generateKeyPair(keyLength.length)
    }

    private external fun generateKeyPair(rsaKeyLength: Int): Array<ByteArray>
}