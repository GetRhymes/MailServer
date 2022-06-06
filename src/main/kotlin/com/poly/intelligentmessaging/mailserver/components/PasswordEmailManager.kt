package com.poly.intelligentmessaging.mailserver.components

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@Component
class PasswordEmailManager {

    @Value("\${password.manager.secret}")
    private val secret: String? = null

    @Value("\${password.manager.encryption-scheme}")
    private val encryptionScheme: String? = null

    fun encrypt(password: String): String {
        val decodedKey = Base64.getDecoder().decode(secret)
        val cipher = Cipher.getInstance(encryptionScheme)
        val originalKey: SecretKey = SecretKeySpec(Arrays.copyOf(decodedKey, 16), encryptionScheme)
        cipher.init(Cipher.ENCRYPT_MODE, originalKey)
        val cipherText = cipher.doFinal(password.toByteArray(charset("UTF-8")))
        return Base64.getEncoder().encodeToString(cipherText)
    }

    fun decrypt(encryptedString: String): String {
        val decodedKey = Base64.getDecoder().decode(secret)
        val cipher = Cipher.getInstance(encryptionScheme)
        val originalKey: SecretKey = SecretKeySpec(Arrays.copyOf(decodedKey, 16), encryptionScheme)
        cipher.init(Cipher.DECRYPT_MODE, originalKey)
        val cipherText = cipher.doFinal(Base64.getDecoder().decode(encryptedString))
        return String(cipherText)
    }
}