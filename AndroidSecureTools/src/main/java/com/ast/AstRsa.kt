package com.ast

import android.content.Context
import android.util.Log
import com.ast.utils.RsaKeyLength

object AstRsa {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKeyPair(context: Context, keyLength: RsaKeyLength) {
        val result = generateKeyPair(keyLength.length, context.packageName)
        Log.d("Alpha", "result ${result[0]} ${result[1]}")
    }

    private external fun generateKeyPair(rsaKeyLength: Int, packageName: String): Array<String>
}