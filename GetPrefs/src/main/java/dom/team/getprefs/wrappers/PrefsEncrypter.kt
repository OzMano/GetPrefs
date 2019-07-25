package dom.team.getprefs.wrappers

import android.util.Base64
import dom.team.getprefs.`interface`.Wrapper
import dom.team.getprefs.constants.GetConstants.algorithm
import dom.team.getprefs.constants.GetConstants.charset
import dom.team.getprefs.constants.GetConstants.transformation
import dom.team.getprefs.exceptions.GetPreferencesException
import java.io.UnsupportedEncodingException
import java.security.GeneralSecurityException
import java.security.KeyException
import java.security.MessageDigest
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class PrefsEncrypter(auth: Pair<String, String>) : Wrapper {

    private var writer: Cipher
    private var reader: Cipher
    private var keyCrypt: Cipher

    init {
        try {
            if (auth.second.isEmpty()) throw IllegalStateException("Encryption key length is 0 [key = ${auth.second}]")

            writer = Cipher.getInstance(transformation)
            reader = Cipher.getInstance(transformation)
            keyCrypt = Cipher.getInstance(transformation)

            initializeCiphers(auth.second)
        } catch (e: GeneralSecurityException) {
            throw GetPreferencesException(e, "Error while initializing the preferences ciphers keys [file = ${auth.first}]")
        } catch (e: UnsupportedEncodingException) {
            throw GetPreferencesException(e, "Error while initializing the preferences ciphers, unsupported charset [file = ${auth.first}].")
        } catch (e: KeyException) {
            throw GetPreferencesException(e, "Error while initializing the preferences ciphers [file = ${auth.first}].")
        }
    }

    private fun initializeCiphers(key: String) {
        val ivSpec = iv
        val secretKey = getSecretKey(key)

        writer.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        reader.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        keyCrypt.init(Cipher.ENCRYPT_MODE, secretKey)
    }

    private fun getSecretKey(key: String): SecretKeySpec {
        val md = MessageDigest.getInstance(algorithm)
        md.reset()
        val keyBytes = md.digest(key.toByteArray(charset(charset)))

        return SecretKeySpec(keyBytes, transformation)
    }

    private val iv: IvParameterSpec
        get() {
            val iv = ByteArray(writer.blockSize)
            System.arraycopy("abcdefghijklmnopqrstuvwxyz123456789".toByteArray(), 0, iv, 0, writer.blockSize)
            return IvParameterSpec(iv)
        }


    override fun encrypt(value: String): String {
        if (value.isEmpty()) return ""
        val encodedValue: ByteArray

        try {
            encodedValue = finalize(writer, value.toByteArray(charset(charset)))
        } catch (e: UnsupportedEncodingException) {
            throw GetPreferencesException(e, "Error while initializing the encryption ciphers, unsupported charset. [value = $value]")
        }

        return Base64.encodeToString(encodedValue, Base64.NO_WRAP)
    }


    override fun decrypt(value: String): String {
        if (value.isEmpty()) return ""
        val encodedValue = Base64.decode(value, Base64.NO_WRAP)
        val finalized = finalize(reader, encodedValue)

        return try {
            String(finalized, Charsets.UTF_8)
        } catch (e: UnsupportedEncodingException) {
            throw GetPreferencesException(e, "Error while initializing the decryption ciphers, unsupported charset. [value = $value]")
        }
    }

    private fun finalize(cipher: Cipher, input: ByteArray): ByteArray {
        try {
            return cipher.doFinal(input)
        } catch (e: IllegalStateException) {
            throw GetPreferencesException(e, "Cipher not initialized (IllegalStateException). input -> [${input.toString(Charsets.UTF_8)}], cipher = $cipher")
        } catch (e: IllegalArgumentException) {
            throw GetPreferencesException(e, "Null input buffer (IllegalArgumentException). input -> [${input.toString(Charsets.UTF_8)}], cipher = $cipher")
        } catch (e: IllegalBlockSizeException) {
            throw GetPreferencesException(e, "Cipher is without padding (IllegalBlockSizeException), you are probably attempting to read a file that is in plain/text format. input = [${input.toString(Charsets.UTF_8)}]")
        } catch (e: BadPaddingException) {
            throw GetPreferencesException(e, "Cipher decryption data is with a wrong padding (BadPaddingException). input = [${input.toString(Charsets.UTF_8)}]")
        }
    }
}