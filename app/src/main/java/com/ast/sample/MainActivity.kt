package com.ast.sample

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.ast.rsa.AstRsa
import com.ast.rsa.RsaKeyLength

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val result = AstRsa.generateKeyPair(this, RsaKeyLength.RSA_KEY_2048)
        val encryptedData = AstRsa.encryptData(result.publicKey, "encrypt string via rsa android")
        val decryptedData = AstRsa.decryptData(result.privateKey, encryptedData)
    }
}