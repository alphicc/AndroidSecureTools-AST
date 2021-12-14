package com.ast.hash

object AstMd5 {

    init {
        System.loadLibrary("android-secure-tools-lib")
    }

    external fun hash(message: String): String
}