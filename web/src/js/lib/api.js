// fetch wrapper for the management API (/api/v1): JSON in and out, CSRF header, Api-Version header, error mapping.
export const API_VERSION = '1'

export class ApiError extends Error {
  constructor(status, body) {
    super((body && body.error) || 'Something went wrong. Please try again.')
    this.status = status
    this.field = (body && body.field) || ''
  }
}

const csrf = () => {
  const m = document.querySelector('meta[name="csrf-token"]')
  return m ? m.content : ''
}

export function qs(params) {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === '' || v === false) continue
    u.set(k, v === true ? '1' : String(v))
  }
  const s = u.toString()
  return s ? '?' + s : ''
}

export async function api(method, url, body, { signal } = {}) {
  const headers = { Accept: 'application/json', 'X-CSRF-Token': csrf() }
  if (url.startsWith('/api/v1')) headers['Api-Version'] = API_VERSION
  const init = { method, headers, credentials: 'same-origin', signal }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  let res
  try {
    res = await fetch(url, init)
  } catch (e) {
    if (e && e.name === 'AbortError') throw e
    throw new ApiError(0, { error: 'The server could not be reached. Check your connection and try again.' })
  }
  let data = null
  if (res.status !== 204) {
    try { data = await res.json() } catch { data = null }
  }
  if (res.status === 401) {
    window.location.assign('/?next=' + encodeURIComponent(location.pathname + location.search))
    throw new ApiError(401, data)
  }
  if (!res.ok) throw new ApiError(res.status, data)
  return data
}

export const get = (url, opts) => api('GET', url, undefined, opts)
export const post = (url, body) => api('POST', url, body === undefined ? {} : body)
export const put = (url, body) => api('PUT', url, body === undefined ? {} : body)
export const patch = (url, body) => api('PATCH', url, body)
export const del = (url) => api('DELETE', url)
