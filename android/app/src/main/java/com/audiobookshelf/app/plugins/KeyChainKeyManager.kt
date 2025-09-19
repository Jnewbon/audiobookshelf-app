package com.audiobookshelf.app.plugins

import android.content.Context
import android.security.KeyChain
import android.util.Log
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.X509KeyManager

/**
 * KeyManager implementation backed directly by Android KeyChain
 * because user-selected client certs are not always visible in AndroidKeyStore.
 */
class KeyChainKeyManager(private val context: Context, private val alias: String) : X509KeyManager {
  private val tag = "KeyChainKeyManager"
  @Volatile private var cachedPrivateKey: PrivateKey? = null
  @Volatile private var cachedChain: Array<X509Certificate>? = null

  private fun ensureLoaded() {
    if (cachedPrivateKey != null && cachedChain != null) return
    synchronized(this) {
      if (cachedPrivateKey != null && cachedChain != null) return
      try {
        val pk = KeyChain.getPrivateKey(context, alias)
          ?: throw IllegalStateException("Private key not accessible for alias $alias")
        val chain = KeyChain.getCertificateChain(context, alias)
          ?: throw IllegalStateException("Certificate chain not found for alias $alias")
        if (chain.isEmpty()) throw IllegalStateException("Empty certificate chain for alias $alias")
        cachedPrivateKey = pk
        @Suppress("UNCHECKED_CAST")
        cachedChain = Array(chain.size) { i -> chain[i] as X509Certificate }
      } catch (e: Exception) {
        Log.e(tag, "Failed loading key/chain for alias $alias", e)
        throw e
      }
    }
  }

  override fun getClientAliases(keyType: String?, issuers: Array<Principal>?): Array<String> = arrayOf(alias)
  override fun chooseClientAlias(keyType: Array<String>?, issuers: Array<Principal>?, socket: Socket?): String = alias
  override fun getServerAliases(keyType: String?, issuers: Array<Principal>?): Array<String>? = null
  override fun chooseServerAlias(keyType: String?, issuers: Array<Principal>?, socket: Socket?): String? = null
  override fun getCertificateChain(alias: String?): Array<X509Certificate> {
    ensureLoaded()
    return cachedChain ?: emptyArray()
  }
  override fun getPrivateKey(alias: String?): PrivateKey {
    ensureLoaded()
    return cachedPrivateKey ?: throw IllegalStateException("Private key not loaded for alias $alias")
  }
}
