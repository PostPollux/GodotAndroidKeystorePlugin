package org.godotengine.plugin.android.keystore

import android.util.Log
import org.godotengine.godot.Godot
import org.godotengine.godot.plugin.GodotPlugin
import org.godotengine.godot.plugin.UsedByGodot
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import java.util.Base64
import java.util.Calendar
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

class GodotAndroidPlugin(godot: Godot): GodotPlugin(godot) {

    override fun getPluginName() = BuildConfig.GODOT_PLUGIN_NAME
   

    /**
     * Überprüft, ob ein Alias im Android Keystore existiert.
     */
    @UsedByGodot
    fun containsAlias(alias: String): Boolean {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            return keyStore.containsAlias(alias)
        } catch (e: Exception) {
            Log.e(pluginName, "Fehler beim Überprüfen des Alias: ${e.message}")
            return false
        }
    }



    /**
     * Deletes an entry with the specified alias from the Android Keystore.
     * @return true if the entry was successfully deleted or false if it failed
     */
    @UsedByGodot
    fun deleteEntry(alias: String): Boolean {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
                Log.v(pluginName, "Key with alias '$alias' removed")
                return true
            } else {
                Log.w(pluginName, "Key with alias '$alias' not found")
                return false
            }
        } catch (e: Exception) {
            Log.e(pluginName, "Error removing key: ${e.message}")
            return false
        }
    }


    /**
     * Generates an AES 256 key in the Android Keystore with the specified alias.
     * Note: If a key with the same alias already exists, it will be overridden.
     * @return true if the key was successfully generated or false if it failed
     */
    @UsedByGodot
    fun generateKey(alias: String): Boolean {
        try {
            val keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
            keyGenerator.init(spec)
            keyGenerator.generateKey()
            Log.v(pluginName, "Key generated with alias: $alias")
            return true
        } catch (e: Exception) {
            Log.e(pluginName, "Error generating key: ${e.message}")
            return false
        }
    }
    
    /**
     * Retrieves the creation date of a key with the specified alias as a Unix timestamp.
     * @return The Unix timestamp (in seconds) of the key's creation date, or -1 if the key doesn't exist or an error occurs.
     */
    @UsedByGodot
    fun getCreationDate(alias: String): Int {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (!keyStore.containsAlias(alias)) {
                Log.w(pluginName, "Key with alias '$alias' not found")
                return -1
            }
            val creationDate = keyStore.getCreationDate(alias)
            return (creationDate.time / 1000).toInt()
        } catch (e: Exception) {
            Log.e(pluginName, "Error retrieving creation date: ${e.message}")
            return -1
        }
    }
    
    
    /**
     * Encrypts a string using the key with the specified alias.
     */
    @UsedByGodot
    fun encryptString(stringToEncrypt: String, alias: String): String {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (!keyStore.containsAlias(alias)) {
                return "Key with alias '$alias' not found"
            }
            val secretKeyEntry = keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry
            val secretKey = secretKeyEntry.secretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val encryptedBytes = cipher.doFinal(stringToEncrypt.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
            return Base64.getEncoder().encodeToString(combined)
        } catch (e: Exception) {
            Log.e(pluginName, "Error encrypting string: ${e.message}")
            return "Encryption error for alias '$alias'"
        }
    }
    
    /**
     * Decrypts a string using the key with the specified alias.
     */
    @UsedByGodot
    fun decryptString(encryptedString: String, alias: String): String {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (!keyStore.containsAlias(alias)) {
                return "Key with alias '$alias' not found"
            }
            val secretKeyEntry = keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry
            val secretKey = secretKeyEntry.secretKey
            val encryptedDataWithIv = Base64.getDecoder().decode(encryptedString)
            val iv = ByteArray(12) // GCM IV length is 12 bytes
            System.arraycopy(encryptedDataWithIv, 0, iv, 0, iv.size)
            val encryptedData = ByteArray(encryptedDataWithIv.size - iv.size)
            System.arraycopy(encryptedDataWithIv, iv.size, encryptedData, 0, encryptedData.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            val decryptedBytes = cipher.doFinal(encryptedData)
            return String(decryptedBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(pluginName, "Error decrypting string: ${e.message}")
            return "Decryption error for alias '$alias'"
        }
    }
}
