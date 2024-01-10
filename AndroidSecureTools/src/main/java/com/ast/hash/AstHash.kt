package com.ast.hash

object AstHash {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    external fun md5(message: String): String

    external fun sha1(message: String): String

    external fun sha256(message: String): String
}