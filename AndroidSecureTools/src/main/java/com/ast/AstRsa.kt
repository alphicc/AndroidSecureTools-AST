package com.ast

import android.util.Log
import com.ast.utils.RsaKeyLength

object AstRsa {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKeyPair(keyLength: RsaKeyLength) {
        val result = generateKeyPair(keyLength.length)
        Log.d("Alpha", "result ${result[0]} ${result[1]}")
    }

    private external fun generateKeyPair(rsaKeyLength: Int): Array<String>
}