import { buildLandingHtml } from './ui/landing.js'
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

const ACCESS_TTL_SECONDS = 60 * 15
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000
const MAX_BODY_SIZE_BYTES = 1_000_000
const SOCIAL_PROVIDERS = new Set(['google', 'github'])

export function createStore() {
  return {
    users: [],
    resetTokens: [],
    refreshTokens: [],
    oauthStates: [],
  }
}

function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = scryptSync(password, salt, 64).toString('hex')
  return `${salt}:${hash}`
}

function comparePassword(password, storedHash) {
  const [salt, hash] = String(storedHash || '').split(':')
  if (!salt || !hash) {
    return false
  }

  const check = scryptSync(password, salt, 64).toString('hex')
  return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'))
}

function signToken(payload, secret, ttlSeconds = ACCESS_TTL_SECONDS) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds
  const data = { ...payload, exp }
  const body = Buffer.from(JSON.stringify(data)).toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

function verifyToken(token, secret) {
  const [body, sig] = String(token || '').split('.')
  if (!body || !sig) {
    throw new Error('token invalido')
  }

  const expectedSig = createHmac('sha256', secret).update(body).digest('base64url')
  const left = Buffer.from(expectedSig)
  const right = Buffer.from(sig)

  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new Error('assinatura de token invalida')
  }

  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('token expirado')
  }

  return payload
}

function issueRefreshToken(store, userId) {
  const token = randomBytes(24).toString('hex')
  const record = {
    token,
    userId,
    expiresAt: Date.now() + REFRESH_TTL_MS,
    revokedAt: null,
  }

  store.refreshTokens.push(record)
  return token
}

function resolveUser(store, userId) {
  const user = store.users.find((item) => item.id === userId)
  if (!user) {
    throw new Error('usuario nao encontrado')
  }
  return user
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    authProviders: [...user.authProviders],
  }
}

function issueSession(store, user, jwtSecret, provider = 'password') {
  user.lastLoginAt = new Date().toISOString()
  const accessToken = signToken({ sub: user.id, email: user.email }, jwtSecret)
  const refreshToken = issueRefreshToken(store, user.id)

  return {
    accessToken,
    refreshToken,
    provider,
    user: publicUser(user),
  }
}

export function createOAuthConfig(overrides = {}) {
  const baseUrl = String(overrides.baseUrl || process.env.APP_BASE_URL || 'http://localhost:3000')

  const google = {
    clientId: String(overrides.google?.clientId || process.env.GOOGLE_CLIENT_ID || '').trim(),
    authorizeUrl: String(overrides.google?.authorizeUrl || 'https://accounts.google.com/o/oauth2/v2/auth'),
    callbackUrl: String(overrides.google?.callbackUrl || `${baseUrl}/auth/social/google/callback`),
    scope: String(overrides.google?.scope || 'openid email profile'),
  }

  const github = {
    clientId: String(overrides.github?.clientId || process.env.GITHUB_CLIENT_ID || '').trim(),
    authorizeUrl: String(overrides.github?.authorizeUrl || 'https://github.com/login/oauth/authorize'),
    callbackUrl: String(overrides.github?.callbackUrl || `${baseUrl}/auth/social/github/callback`),
    scope: String(overrides.github?.scope || 'read:user user:email'),
  }

  return { google, github }
}

function resolveProviderConfig(oauthConfig, providerId) {
  if (!SOCIAL_PROVIDERS.has(providerId)) {
    throw new Error('provider social invalido')
  }

  const config = oauthConfig[providerId]
  if (!config) {
    throw new Error('provider social invalido')
  }

  return config
}

export function providersStatus(oauthConfig = createOAuthConfig()) {
  return {
    google: {
      enabled: Boolean(oauthConfig.google?.clientId),
      callbackUrl: oauthConfig.google?.callbackUrl || '',
    },
    github: {
      enabled: Boolean(oauthConfig.github?.clientId),
      callbackUrl: oauthConfig.github?.callbackUrl || '',
    },
  }
}

export function registerUser(store, { name, email, password }) {
  const normalizedEmail = String(email || '').trim().toLowerCase()
  if (!name || !normalizedEmail || !password) {
    throw new Error('name, email e password sao obrigatorios')
  }

  if (password.length < 8) {
    throw new Error('password precisa ter ao menos 8 caracteres')
  }

  const existing = store.users.find((user) => user.email === normalizedEmail)
  if (existing?.passwordHash) {
    throw new Error('email ja cadastrado')
  }

  if (existing && !existing.passwordHash) {
    existing.passwordHash = hashPassword(password)
    if (!existing.authProviders.includes('password')) {
      existing.authProviders.push('password')
    }
    if (String(name).trim()) {
      existing.name = String(name).trim()
    }
    existing.updatedAt = new Date().toISOString()
    return publicUser(existing)
  }

  const user = {
    id: randomBytes(8).toString('hex'),
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash: hashPassword(password),
    authProviders: ['password'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastLoginAt: null,
  }

  store.users.push(user)
  return publicUser(user)
}

export function socialLogin(store, { provider, email, name }, jwtSecret) {
  const providerId = String(provider || '').trim().toLowerCase()
  if (!SOCIAL_PROVIDERS.has(providerId)) {
    throw new Error('provider social invalido')
  }

  const normalizedEmail = String(email || '').trim().toLowerCase()
  if (!normalizedEmail) {
    throw new Error('email e obrigatorio para login social')
  }

  let user = store.users.find((item) => item.email === normalizedEmail)

  if (!user) {
    user = {
      id: randomBytes(8).toString('hex'),
      name: String(name || normalizedEmail.split('@')[0]).trim(),
      email: normalizedEmail,
      passwordHash: null,
      authProviders: [providerId],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastLoginAt: null,
    }
    store.users.push(user)
  } else {
    if (!user.authProviders.includes(providerId)) {
      user.authProviders.push(providerId)
    }
    if (String(name || '').trim()) {
      user.name = String(name).trim()
    }
    user.updatedAt = new Date().toISOString()
  }

  return issueSession(store, user, jwtSecret, providerId)
}

export function loginUser(store, { email, password }, jwtSecret) {
  const normalizedEmail = String(email || '').trim().toLowerCase()
  const user = store.users.find((item) => item.email === normalizedEmail)

  if (!user) {
    throw new Error('credenciais invalidas')
  }

  if (!user.passwordHash) {
    throw new Error('conta vinculada a login social; defina uma senha para login por email')
  }

  if (!comparePassword(String(password || ''), user.passwordHash)) {
    throw new Error('credenciais invalidas')
  }

  return issueSession(store, user, jwtSecret)
}

export function refreshSession(store, { refreshToken }, jwtSecret) {
  const record = store.refreshTokens.find((item) => item.token === refreshToken)
  if (!record || record.revokedAt || record.expiresAt < Date.now()) {
    throw new Error('refresh token invalido ou expirado')
  }

  const user = resolveUser(store, record.userId)
  const accessToken = signToken({ sub: user.id, email: user.email }, jwtSecret)

  return {
    accessToken,
    user: publicUser(user),
  }
}

export function authMe(store, authorizationHeader, jwtSecret) {
  const value = String(authorizationHeader || '')
  if (!value.startsWith('Bearer ')) {
    throw new Error('token bearer ausente')
  }

  const token = value.slice('Bearer '.length)
  const payload = verifyToken(token, jwtSecret)
  const user = resolveUser(store, payload.sub)

  return publicUser(user)
}

export function requestPasswordReset(store, { email }) {
  const normalizedEmail = String(email || '').trim().toLowerCase()
  const user = store.users.find((item) => item.email === normalizedEmail)
  if (!user) {
    return { message: 'Se o email existir, enviaremos instrucoes.' }
  }

  const token = randomBytes(20).toString('hex')
  const expiresAt = Date.now() + 15 * 60 * 1000
  store.resetTokens.push({ token, userId: user.id, expiresAt, usedAt: null })

  return { token, expiresAt }
}

export function resetPassword(store, { token, newPassword }) {
  if (!token || !newPassword) {
    throw new Error('token e newPassword sao obrigatorios')
  }

  const record = store.resetTokens.find((item) => item.token === token)
  if (!record || record.usedAt || record.expiresAt < Date.now()) {
    throw new Error('token invalido ou expirado')
  }

  if (newPassword.length < 8) {
    throw new Error('newPassword precisa ter ao menos 8 caracteres')
  }

  const user = resolveUser(store, record.userId)
  user.passwordHash = hashPassword(newPassword)
  if (!user.authProviders.includes('password')) {
    user.authProviders.push('password')
  }
  user.updatedAt = new Date().toISOString()
  record.usedAt = Date.now()

  return { message: 'senha atualizada com sucesso' }
}

export function createOAuthState(store, provider) {
  const state = randomBytes(12).toString('hex')
  store.oauthStates.push({
    state,
    provider,
    expiresAt: Date.now() + OAUTH_STATE_TTL_MS,
    usedAt: null,
  })
  return state
}

export function consumeOAuthState(store, provider, state) {
  const item = store.oauthStates.find((entry) => entry.state === state && entry.provider === provider)
  if (!item || item.usedAt || item.expiresAt < Date.now()) {
    throw new Error('state oauth invalido ou expirado')
  }
  item.usedAt = Date.now()
}

export function buildOAuthAuthorizeUrl(providerConfig, state) {
  if (!providerConfig.clientId) {
    throw new Error('provider nao configurado')
  }

  const url = new URL(providerConfig.authorizeUrl)
  url.searchParams.set('client_id', providerConfig.clientId)
  url.searchParams.set('redirect_uri', providerConfig.callbackUrl)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', providerConfig.scope)
  url.searchParams.set('state', state)
  return url.toString()
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'content-type': 'application/json' })
  res.end(JSON.stringify(payload))
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let totalSize = 0
    req.on('data', (chunk) => {
      totalSize += chunk.length
      if (totalSize > MAX_BODY_SIZE_BYTES) {
        reject(new Error('payload excede limite de 1MB'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (!chunks.length) {
        resolve({})
        return
      }

      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new Error('JSON invalido'))
      }
    })
    req.on('error', reject)
  })
}

export function createApp(
  store = createStore(),
  jwtSecret = process.env.JWT_SECRET || 'dev-secret',
  options = {}
) {
  const oauthConfig = options.oauthConfig || createOAuthConfig()

  return async function app(req, res) {
    const url = new URL(req.url || '/', 'http://localhost')

    try {
            if (req.method === 'GET' && url.pathname === '/') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end(buildLandingHtml())
        return
      }

      if (req.method === 'GET' && url.pathname === '/health') {
        sendJson(res, 200, { ok: true, service: 'secure-auth-template' })
        return
      }

      if (req.method === 'GET' && url.pathname === '/auth/providers') {
        sendJson(res, 200, providersStatus(oauthConfig))
        return
      }

      if (req.method === 'POST' && url.pathname === '/auth/register') {
        const payload = await readJsonBody(req)
        const user = registerUser(store, payload)
        sendJson(res, 201, { user })
        return
      }

      if (req.method === 'POST' && url.pathname === '/auth/login') {
        const payload = await readJsonBody(req)
        const session = loginUser(store, payload, jwtSecret)
        sendJson(res, 200, session)
        return
      }

      const socialAuthorizeMatch = url.pathname.match(/^\/auth\/social\/([^/]+)\/authorize$/)
      if (req.method === 'GET' && socialAuthorizeMatch) {
        const provider = String(socialAuthorizeMatch[1]).toLowerCase()
        const providerConfig = resolveProviderConfig(oauthConfig, provider)
        const state = createOAuthState(store, provider)
        const authorizeUrl = buildOAuthAuthorizeUrl(providerConfig, state)
        sendJson(res, 200, {
          provider,
          state,
          authorizeUrl,
          callbackUrl: providerConfig.callbackUrl,
        })
        return
      }

      const socialCallbackMatch = url.pathname.match(/^\/auth\/social\/([^/]+)\/callback$/)
      if (req.method === 'POST' && socialCallbackMatch) {
        const provider = String(socialCallbackMatch[1]).toLowerCase()
        const providerConfig = resolveProviderConfig(oauthConfig, provider)
        if (!providerConfig.clientId) {
          throw new Error('provider nao configurado')
        }

        const payload = await readJsonBody(req)
        consumeOAuthState(store, provider, String(payload.state || ''))

        const session = socialLogin(
          store,
          {
            provider,
            email: payload.email,
            name: payload.name,
          },
          jwtSecret
        )
        sendJson(res, 200, session)
        return
      }

      if (req.method === 'POST' && url.pathname === '/auth/refresh') {
        const payload = await readJsonBody(req)
        const session = refreshSession(store, payload, jwtSecret)
        sendJson(res, 200, session)
        return
      }

      if (req.method === 'GET' && url.pathname === '/auth/me') {
        const user = authMe(store, req.headers.authorization, jwtSecret)
        sendJson(res, 200, { user })
        return
      }

      if (req.method === 'POST' && url.pathname === '/auth/forgot-password') {
        const payload = await readJsonBody(req)
        const result = requestPasswordReset(store, payload)
        sendJson(res, 200, result)
        return
      }

      if (req.method === 'POST' && url.pathname === '/auth/reset-password') {
        const payload = await readJsonBody(req)
        const result = resetPassword(store, payload)
        sendJson(res, 200, result)
        return
      }

      sendJson(res, 404, { error: 'rota nao encontrada' })
    } catch (error) {
      sendJson(res, 400, { error: error instanceof Error ? error.message : 'erro inesperado' })
    }
  }
}


