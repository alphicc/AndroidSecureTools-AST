package com.ast.rsa

import android.content.Context
import androidx.annotation.WorkerThread
import com.ast.rsa.models.RsaKeys
import kotlin.jvm.Throws

@WorkerThread
object AstRsa {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKeyPair(context: Context, keyLength: RsaKeyType): RsaKeys {
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
        keyLength: RsaKeyType,
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

    fun encryptData(publicKey: String, data: String): String = encryptString(publicKey, data)

    fun decryptData(privateKey: String, data: String): String = decryptString(privateKey, data.trim())

    private external fun generateKeyPair(
        rsaKeyLength: Int,
        packageName: String,
        encryptPrivateKey: Boolean,
        passphrase: String
    ): Array<String>

    private external fun encryptString(publicKey: String, data: String): String

    private external fun decryptString(privateKey: String, data: String): String
}