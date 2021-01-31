package com.ast.rsa

import android.content.Context
import com.ast.rsa.models.RsaKeys
import kotlin.jvm.Throws

object AstRsa {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKeyPair(context: Context, keyLength: RsaKeyLength): RsaKeys {
        val result = generateKeyPair(
            keyLength.length,
            context.packageName,
            false,
            ""
        )
        return RsaKeys(result[0], result[1])
    }

    fun generateKeyPair(
        context: Context,
        keyLength: RsaKeyLength,
        encryptPrivateKey: Boolean,
        passphrase: String
    ): RsaKeys {
        val result =
            generateKeyPair(
                keyLength.length,
                context.packageName,
                encryptPrivateKey,
                passphrase
            )
        return RsaKeys(result[0], result[1])
    }

    @Throws(java.lang.Exception::class)
    fun encryptData(publicKey: String, data: String): String = encryptString(publicKey, data)

    private external fun generateKeyPair(
        rsaKeyLength: Int,
        packageName: String,
        encryptPrivateKey: Boolean,
        passphrase: String
    ): Array<String>

    private external fun encryptString(publicKey: String, data: String): String
}