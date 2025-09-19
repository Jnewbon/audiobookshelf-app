package com.audiobookshelf.app.plugins

import android.security.KeyChain
import android.security.KeyChainAliasCallback
import android.util.Log
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import java.io.IOException
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Capacitor plugin to enable mutual TLS using a client certificate picked from the Android system KeyChain.
 */
@CapacitorPlugin(name = "ClientCert")
class ClientCert : Plugin() {
  private val tag = "ClientCertPlugin"
  @Volatile private var okHttpClient: OkHttpClient? = null
  @Volatile private var currentAlias: String? = null

  /* ======================= Public API ======================= */

  @PluginMethod
  fun pickCertificate(call: PluginCall) {
    val activity = activity
    // Restrict to common key algorithms to avoid showing incompatible certs
    val keyTypes = arrayOf("RSA", "EC")
    KeyChain.choosePrivateKeyAlias(activity, object : KeyChainAliasCallback {
      override fun alias(alias: String?) {
        if (alias == null) {
          call.reject("User canceled")
          return
        }
        Log.d(tag, "Picked alias $alias")
        val ret = JSObject()
        ret.put("alias", alias)
        call.resolve(ret)
      }
    }, keyTypes, null, null, -1, null)
  }

  @PluginMethod
  fun enableClientCert(call: PluginCall) {
    val alias = call.getString("alias")
    if (alias.isNullOrBlank()) {
      call.reject("alias required")
      return
    }
    try {
      // Build KeyManager directly from KeyChain
      val keyManager = KeyChainKeyManager(context, alias)
      // Force-load key & chain early to give immediate feedback
      keyManager.getPrivateKey(alias) // triggers ensureLoaded()
      val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
      tmf.init(null as KeyStore?)
      val trustManagers = tmf.trustManagers
      val x509Tm = trustManagers.filterIsInstance<X509TrustManager>().first()
      val sslContext = SSLContext.getInstance("TLS")
      sslContext.init(arrayOf<KeyManager>(keyManager), trustManagers, SecureRandom())

      okHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, x509Tm)
        .build()
      currentAlias = alias

      val ret = JSObject()
      ret.put("enabled", true)
      ret.put("alias", alias)
      call.resolve(ret)
    } catch (e: Exception) {
      Log.e(tag, "Failed enabling client cert", e)
      call.reject("Failed enabling client cert: ${e.message}", e)
    }
  }

  @PluginMethod
  fun disableClientCert(call: PluginCall) {
    okHttpClient = null
    currentAlias = null
    val ret = JSObject()
    ret.put("disabled", true)
    call.resolve(ret)
  }

  @PluginMethod
  fun get(call: PluginCall) {
    val url = call.getString("url")
    if (url.isNullOrBlank()) return call.reject("url required")
    val headersObj = call.getObject("headers")
    val builder = Request.Builder().url(url)
    headersObj?.keys()?.forEach { key ->
      val hv = headersObj.optString(key, null)
      if (!hv.isNullOrEmpty()) builder.addHeader(key, hv)
    }
    makeCall(call, builder.get().build())
  }

  @PluginMethod
  fun post(call: PluginCall) {
    val url = call.getString("url")
    if (url.isNullOrBlank()) return call.reject("url required")
    val bodyStr = call.getString("body") ?: "{}"
    val headersObj = call.getObject("headers")
    val mediaType = "application/json; charset=utf-8".toMediaType()
    val rb = bodyStr.toRequestBody(mediaType)
    val builder = Request.Builder().url(url).post(rb)
    headersObj?.keys()?.forEach { key ->
      val hv = headersObj.optString(key, null)
      if (!hv.isNullOrEmpty()) builder.addHeader(key, hv)
    }
    makeCall(call, builder.build())
  }

  /* ======================= Internal helpers ======================= */

  private fun client(): OkHttpClient = okHttpClient ?: OkHttpClient()

  private fun makeCall(call: PluginCall, request: Request) {
    client().newCall(request).enqueue(object: Callback {
      override fun onFailure(callOk: Call, e: IOException) {
        call.reject(e.message, e)
      }

      override fun onResponse(callOk: Call, response: Response) {
        response.use { resp ->
          try {
            val bodyStr = resp.body?.string() ?: ""
            val ret = JSObject()
            ret.put("status", resp.code)
            ret.put("data", bodyStr)
            ret.put("aliasUsed", currentAlias != null)
            call.resolve(ret)
          } catch (e: Exception) {
            call.reject(e.message, e)
          }
        }
      }
    })
  }
}
