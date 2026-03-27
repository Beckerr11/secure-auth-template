import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

export function createStore() {
  return {
    users: [],
    resetTokens: [],
  }
}

function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const hash = scryptSync(password, salt, 64).toString('hex')
  return `${salt}:${hash}`
}

function comparePassword(password, storedHash) {
  const [salt, hash] = String(storedHash).split(':')
  const check = scryptSync(password, salt, 64).toString('hex')
  return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'))
}

function signToken(payload, secret, ttlSeconds = 3600) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds
  const data = { ...payload, exp }
  const body = Buffer.from(JSON.stringify(data)).toString('base64url')
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

export function registerUser(store, { name, email, password }) {
  const normalizedEmail = String(email || '').trim().toLowerCase()
  if (!name || !normalizedEmail || !password) {
    throw new Error('name, email e password sao obrigatorios')
  }

  if (password.length < 8) {
    throw new Error('password precisa ter ao menos 8 caracteres')
  }

  if (store.users.some((user) => user.email === normalizedEmail)) {
    throw new Error('email ja cadastrado')
  }

  const user = {
    id: randomBytes(8).toString('hex'),
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
  }

  store.users.push(user)
  return { id: user.id, name: user.name, email: user.email }
}

export function loginUser(store, { email, password }, jwtSecret) {
  const normalizedEmail = String(email || '').trim().toLowerCase()
  const user = store.users.find((item) => item.email === normalizedEmail)

  if (!user || !comparePassword(String(password || ''), user.passwordHash)) {
    throw new Error('credenciais invalidas')
  }

  return {
    token: signToken({ sub: user.id, email: user.email }, jwtSecret),
    user: { id: user.id, name: user.name, email: user.email },
  }
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

  const user = store.users.find((item) => item.id === record.userId)
  if (!user) {
    throw new Error('usuario nao encontrado')
  }

  user.passwordHash = hashPassword(newPassword)
  record.usedAt = Date.now()

  return { message: 'senha atualizada com sucesso' }
}

export function providersStatus() {
  return {
    google: true,
    github: true,
  }
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'content-type': 'application/json' })
  res.end(JSON.stringify(payload))
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
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

export function createApp(store = createStore(), jwtSecret = process.env.JWT_SECRET || 'dev-secret') {
  return async function app(req, res) {
    const url = new URL(req.url || '/', 'http://localhost')

    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        sendJson(res, 200, { ok: true, service: 'secure-auth-template' })
        return
      }

      if (req.method === 'GET' && url.pathname === '/auth/providers') {
        sendJson(res, 200, providersStatus())
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