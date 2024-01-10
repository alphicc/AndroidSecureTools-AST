package com.ast

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ast.rsa.AstRsa
import com.ast.rsa.RsaKeyType
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RsaTest {

    @Test
    fun keyGenerationTest() {
        val keys = arrayOf(
            RsaKeyType.RSA_KEY_512,
            RsaKeyType.RSA_KEY_1024,
            RsaKeyType.RSA_KEY_2048,
            RsaKeyType.RSA_KEY_4096,
            RsaKeyType.RSA_KEY_8192
        )
        keys.forEach {
            val appContext = InstrumentationRegistry.getInstrumentation().targetContext
            val rsaKeys = AstRsa.generateKeyPair(appContext, it)
            assertTrue(rsaKeys.privateKey.isNotEmpty() && rsaKeys.publicKey.isNotEmpty())
        }
    }

    @Test
    fun complexTest() {
        val keys = arrayOf(
            RsaKeyType.RSA_KEY_1024,
            RsaKeyType.RSA_KEY_2048,
            RsaKeyType.RSA_KEY_4096,
            RsaKeyType.RSA_KEY_8192
        )
        val messages = arrayOf(
            "",
            "1",
            "%^#*&*$!764981798^&!^&*$^!&*^&$$",
            "斯会文 社 ═╬ ╬═ ۩۞۩ ★★★ ▀▄",
            "๏̯͡๏ 斯坦尼斯会文 社 ═╬ ╬═ ۩۞۩ ★★★ ▀▄",
            "AAAAAAAAAAAAAAAAAAAAAAAAAADSDADADAD***************************AAAAAAAAAAAAAAAAAAAAAAAAAAADSDADADAD******************9"
        )
        keys.forEach { key ->
            messages.forEach { message ->
                val isSame = isRsaCryptoResultsSame(message, key)
                assertTrue(isSame)
            }
        }
    }

    private fun isRsaCryptoResultsSame(
        testMessage: String,
        rsaKeyType: RsaKeyType
    ): Boolean {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val rsaKeys = AstRsa.generateKeyPair(appContext, rsaKeyType)
        val encryptedData = AstRsa.encryptData(rsaKeys.publicKey, testMessage)
        val decryptedData = AstRsa.decryptData(rsaKeys.privateKey, encryptedData)
        return decryptedData == testMessage
    }
}