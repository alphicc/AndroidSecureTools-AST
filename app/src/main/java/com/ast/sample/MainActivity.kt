package com.ast.sample

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.ast.aes.AesKeyType
import com.ast.aes.AstAes
import com.ast.aes.Cipher
import com.ast.rsa.AstRsa
import com.ast.rsa.RsaKeyType

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val result = AstRsa.generateKeyPair(this, RsaKeyType.RSA_KEY_2048)
        val encryptedData = AstRsa.encryptData(result.publicKey, "encrypt string via rsa android")
        val decryptedData = AstRsa.decryptData(result.privateKey, encryptedData)
        val aesKeyGenResult = AstAes.generateKey(AesKeyType.L_256)
        val encryptedMessage = AstAes.encryptMessage(
            Cipher.CBC_256,
            aesKeyGenResult.key,
            aesKeyGenResult.iv,
            "encrypt string via rsa android"
        )
        val decryptedMessage = AstAes.decryptMessage(
            Cipher.CBC_256,
            aesKeyGenResult.key,
            aesKeyGenResult.iv,
            encryptedMessage
        )
    }
}