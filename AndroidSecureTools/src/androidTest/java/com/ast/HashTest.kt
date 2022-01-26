package com.ast

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ast.hash.AstHash
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HashTest {

    @Test
    fun md5Test() {
        val data = listOf(
            "",
            "  ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "斯会文 社 ═╬ ╬═ ۩۞۩ ★★★ ▀▄"
        )
        data.forEach {
            val result = AstHash.md5(it)
            if (result.isEmpty()) {
                throw IllegalStateException("result can't be empty")
            }
        }
    }

    @Test
    fun sha1Test() {
        val data = listOf(
            "",
            "  ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "斯会文 社 ═╬ ╬═ ۩۞۩ ★★★ ▀▄"
        )
        data.forEach {
            val result = AstHash.sha1(it)
            if (result.isEmpty()) {
                throw IllegalStateException("result can't be empty")
            }
        }
    }

    @Test
    fun sha256Test() {
        val data = listOf(
            "",
            "  ",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "斯会文 社 ═╬ ╬═ ۩۞۩ ★★★ ▀▄"
        )
        data.forEach {
            val result = AstHash.sha256(it)
            if (result.isEmpty()) {
                throw IllegalStateException("result can't be empty")
            }
        }
    }
}