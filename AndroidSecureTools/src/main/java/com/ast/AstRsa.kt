package com.ast

import android.content.Context
import android.util.Log
import com.ast.utils.RsaKeyLength

object AstRsa {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKeyPair(context: Context, keyLength: RsaKeyLength) {
        val result = generateKeyPair(keyLength.length, context.packageName, false, "")
        //result.forEach {
        //    Log.d("Alpha", "key\n $it")
        //}
    }

    fun generateKeyPair(
        context: Context,
        keyLength: RsaKeyLength,
        encryptPrivateKey: Boolean,
        passphrase: String
    ) {
        val result =
            generateKeyPair(keyLength.length, context.packageName, encryptPrivateKey, passphrase)
    }

    private external fun generateKeyPair(
        rsaKeyLength: Int,
        packageName: String,
        encryptPrivateKey: Boolean,
        passphrase: String
    ): Array<String>
}