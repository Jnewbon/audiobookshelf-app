// Wrapper for Android system client cert based mutual TLS HTTP requests
// Injects $systemMtlsHttp with pick/enable/disable/get/post helpers.
// Safe no-op on unsupported platforms (web/iOS until implemented).

export default function (_ctx, inject) {
  const pluginRef = () => (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.ClientCert) || null

  async function call(method, args) {
    const p = pluginRef()
    if (!p) throw new Error('ClientCert plugin not available')
    return p[method](args || {})
  }

  function tryParse(data) {
    if (data == null) return data
    if (typeof data !== 'string') return data
    try {
      return JSON.parse(data)
    } catch (_) {
      return data
    }
  }

  const systemMtlsHttp = {
    alias: null,
    available: false,
    supported() { return this.available },
    _ensureAvailableChecksStarted: false,

    _startAvailabilityChecks() {
      if (this._ensureAvailableChecksStarted) return
      this._ensureAvailableChecksStarted = true
      const tryMark = () => {
        const p = pluginRef()
        if (p && !this.available) {
          this.available = true
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('clientcert-available'))
          }
        }
      }
      // Initial quick attempts
      let attempts = 0
      const interval = setInterval(() => {
        attempts++
        tryMark()
        if (this.available || attempts > 50) clearInterval(interval)
      }, 120)
      // Also check on deviceready
      if (typeof document !== 'undefined') {
        document.addEventListener('deviceready', () => {
          tryMark()
        }, { once: true })
      }
      // Fallback late check after 5s
      setTimeout(tryMark, 5000)
    },

    async pickCertificate() {
      if (!this.available) throw new Error('ClientCert plugin not available')
      const res = await call('pickCertificate')
      this.alias = res.alias
      return res.alias
    },
    async enable(alias) {
      if (!this.available) throw new Error('ClientCert plugin not available')
      alias = alias || this.alias
      if (!alias) throw new Error('No alias selected')
      await call('enableClientCert', { alias })
      this.alias = alias
      return alias
    },
    async disable() {
      if (!this.available) return
      await call('disableClientCert')
      this.alias = null
    },
    async get(url, headers = {}) {
      console.info('[systemMtlsHttp] get entered')
      if (!this.available) throw new Error('ClientCert plugin not available')
      const res = await call('get', { url, headers })
      return { status: res.status, data: tryParse(res.data), url }
    },
    async post(url, body = {}, headers = {}) {
      if (!this.available) throw new Error('ClientCert plugin not available')
      const res = await call('post', { url, headers, body: JSON.stringify(body) })
      return { status: res.status, data: tryParse(res.data), url }
    }
  }

  systemMtlsHttp._startAvailabilityChecks()

  inject('systemMtlsHttp', systemMtlsHttp)
}
