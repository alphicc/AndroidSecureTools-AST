package com.ast.rsa

enum class RsaKeyLength(val length: Int) {
    RSA_KEY_512(512),
    RSA_KEY_1024(1024),
    RSA_KEY_2048(2048),
    RSA_KEY_4096(4096),
    RSA_KEY_8192(8192)
}