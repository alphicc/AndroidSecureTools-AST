package com.ast.aes

import com.ast.aes.models.AesKeyGenResult

object AstAes {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    fun generateKey(keyType: AesKeyType): AesKeyGenResult = generateKey(keyType.value)

    fun encryptMessage(cipher: Cipher, key: String, iv: String, message: String): String =
        encryptMessage(cipher.value, key, iv, message)

    fun decryptMessage(cipher: Cipher, key: String, iv: String, message: String): String =
        decryptMessage(cipher.value, key, iv, message)

    private external fun decryptMessage(
        cipher: Int,
        key: String,
        iv: String,
        message: String
    ): String

    private external fun encryptMessage(
        cipher: Int,
        key: String,
        iv: String,
        message: String
    ): String

    private external fun generateKey(keyType: Int): AesKeyGenResult
}