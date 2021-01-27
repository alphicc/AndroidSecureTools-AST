package com.ast

import android.content.Context
import android.util.Log
import com.ast.utils.RsaKeyLength

object AstRsa {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKeyPair(context: Context, keyLength: RsaKeyLength) {
        try {
            val result = generateKeyPair(keyLength.length, context.packageName, false, "")
        } catch (exception: Exception) {
            Log.d("Alpha", " Throw ${exception.message}")
        }
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

    private external fun encryptString(publicKey: String, data: String): String
}