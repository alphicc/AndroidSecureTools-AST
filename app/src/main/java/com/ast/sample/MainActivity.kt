package com.ast.sample

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.ast.hash.AstHash

class MainActivity : AppCompatActivity() {

    @SuppressLint("WrongThread")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val hash = AstHash.md5(message = "123")
        Log.d("Alpha", "Hash Result = $hash")

        val hashsha1 = AstHash.sha1(message = "123")
        Log.d("Alpha", "Sha1 Hash Result = $hashsha1")

        val hashsha256 = AstHash.sha256(message = "123")
        Log.d("Alpha", "Sha256 Hash Result = $hashsha256")
        //var rsaKeys = AstRsa.generateKeyPair(this, RsaKeyType.RSA_KEY_8192)
        //Log.d("Alpha", "${rsaKeys.publicKey}\n===\n${rsaKeys.privateKey}")
        //val encryptedData1 = AstRsa.encryptData(rsaKeys.publicKey, "1")
        //Log.d("Alpha", "encryptedData1 ${encryptedData1}")
        //val decryptedData1 = AstRsa.decryptData(rsaKeys.privateKey, encryptedData1)
        // Log.d("Alpha", "decryptedData1 ${decryptedData1}")

        //val result = AstRsa.generateKeyPair(this, RsaKeyType.RSA_KEY_2048)
        //Log.d("DebugInfo", "\n${result.publicKey}\n${result.privateKey}")
        //val encryptedData = AstRsa.encryptData(result.publicKey, "encrypt string via rsa android")
        //Log.d("DebugInfo", "encryptedData \n$encryptedData")
        //val decryptedData = AstRsa.decryptData(result.privateKey, encryptedData)
        //Log.d("DebugInfo", "decryptedData \n$decryptedData")
        //val aesKeyGenResult = AstAes.generateKey(AesKeyType.L_256)
        ////Log.d("DebugInfo", "aesKeyGenResult \n${aesKeyGenResult}")
        //val encryptedMessage = AstAes.encryptMessage(
        //    Cipher.CBC_256,
        //    aesKeyGenResult.key,
        //    aesKeyGenResult.iv,
        //    "encrypt string via rsa android"
        //)
        //val decryptedMessage = AstAes.decryptMessage(
        //    Cipher.CBC_256,
        //    aesKeyGenResult.key,
        //    aesKeyGenResult.iv,
        //    encryptedMessage
        //)
    }
}