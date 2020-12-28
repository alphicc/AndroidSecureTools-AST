package com.ast.sample

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.ast.AstRsa
import com.ast.utils.RsaKeyLength

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        AstRsa.generateKeyPair(this, RsaKeyLength.RSA_KEY_2048)
    }
}