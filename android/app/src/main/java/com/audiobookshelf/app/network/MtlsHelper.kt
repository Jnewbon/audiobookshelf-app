package com.audiobookshelf.app.network

import android.content.Context
import android.util.Log
import android.util.Base64
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import okhttp3.OkHttpClient
import javax.net.ssl.TrustManagerFactory

object MtlsHelper {
    private const val TAG = "MtlsHelper"

    /**
     * Loads a client certificate and private key from PEM strings and builds an SSLSocketFactory.
     * @param context Android context
     * @param certPem PEM-encoded X.509 certificate string
     * @param keyPem PEM-encoded PKCS#8 private key string
     * @return Pair of SSLSocketFactory and KeyManagerFactory
     */
    fun buildMtlsSocketFactory(context: Context, certPem: String, keyPem: String): Pair<SSLSocketFactory, KeyManagerFactory> {
        Log.d(TAG, "Initializing mTLS socket factory (cert length=${certPem.length}, key length=${keyPem.length})")
        val certificate = parseCertificate(certPem)
        val privateKey = parsePrivateKey(keyPem)
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        keyStore.load(null, null)
        keyStore.setKeyEntry("client", privateKey, null, arrayOf(certificate))

        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, null)

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, null, null)
        Log.d(TAG, "mTLS SSLContext initialized with client cert subject=${certificate.subjectDN}")
        return Pair(sslContext.socketFactory, kmf)
    }

    private fun stripPemHeaders(input: String): String = input
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replace("\n", "")
        .replace("\r", "")
        .trim()

    private fun parseCertificate(certPem: String): X509Certificate {
        val cleaned = stripPemHeaders(certPem)
        val decoded = Base64.decode(cleaned, Base64.DEFAULT)
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(decoded)) as X509Certificate
    }

    private fun parsePrivateKey(keyPem: String): PrivateKey {
        // Expect PKCS#8. If RSA PKCS#1 is provided we currently log and throw.
        val isPkcs1Rsa = keyPem.contains("BEGIN RSA PRIVATE KEY")
        if (isPkcs1Rsa) {
            Log.e(TAG, "PKCS#1 (BEGIN RSA PRIVATE KEY) provided. Convert to PKCS#8: openssl pkcs8 -topk8 -inform PEM -outform PEM -in key.pem -out key_pkcs8.pem -nocrypt")
        }
        val cleaned = stripPemHeaders(keyPem)
        val decoded = Base64.decode(cleaned, Base64.DEFAULT)
        val keySpec = PKCS8EncodedKeySpec(decoded)
        // Try RSA first then fallback EC
        return try {
            KeyFactory.getInstance("RSA").generatePrivate(keySpec)
        } catch (e: Exception) {
            Log.d(TAG, "Not RSA key, trying EC: ${e.message}")
            KeyFactory.getInstance("EC").generatePrivate(keySpec)
        }
    }

    /**
     * Builds an OkHttpClient with mTLS enabled using the provided cert and key.
     */
    fun buildMtlsOkHttpClient(context: Context, certPem: String, keyPem: String): OkHttpClient {
        val (sslSocketFactory, _) = buildMtlsSocketFactory(context, certPem, keyPem)
        val trustManager = systemDefaultTrustManager()
        return OkHttpClient.Builder()
            .sslSocketFactory(sslSocketFactory, trustManager)
            .build()
    }

    // Helper to get the system default X509TrustManager
    private fun systemDefaultTrustManager(): javax.net.ssl.X509TrustManager {
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as KeyStore?)
        val trustManagers = trustManagerFactory.trustManagers
        return trustManagers.first { it is javax.net.ssl.X509TrustManager } as javax.net.ssl.X509TrustManager
    }
}
