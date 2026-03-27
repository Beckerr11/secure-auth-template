import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createStore,
  registerUser,
  loginUser,
  socialLogin,
  refreshSession,
  authMe,
  requestPasswordReset,
  resetPassword,
  createOAuthConfig,
  providersStatus,
} from '../src/app.js'

test('register, login, me, refresh and password reset flow', () => {
  const store = createStore()
  const secret = 'secret-test'

  registerUser(store, { name: 'Douglas', email: 'douglas@example.com', password: 'SenhaSegura123' })

  const login = loginUser(store, { email: 'douglas@example.com', password: 'SenhaSegura123' }, secret)
  assert.ok(login.accessToken)
  assert.ok(login.refreshToken)

  const me = authMe(store, `Bearer ${login.accessToken}`, secret)
  assert.equal(me.email, 'douglas@example.com')

  const refreshed = refreshSession(store, { refreshToken: login.refreshToken }, secret)
  assert.ok(refreshed.accessToken)

  const reset = requestPasswordReset(store, { email: 'douglas@example.com' })
  const result = resetPassword(store, { token: reset.token, newPassword: 'NovaSenha1234' })
  assert.equal(result.message, 'senha atualizada com sucesso')

  const relogin = loginUser(store, { email: 'douglas@example.com', password: 'NovaSenha1234' }, secret)
  assert.ok(relogin.accessToken)
})

test('social user can define password and login locally', () => {
  const store = createStore()
  const secret = 'secret-test'

  const socialSession = socialLogin(
    store,
    { provider: 'google', email: 'social@example.com', name: 'Social User' },
    secret
  )
  assert.equal(socialSession.provider, 'google')

  assert.throws(
    () => loginUser(store, { email: 'social@example.com', password: 'Teste1234' }, secret),
    /login social/
  )

  const upgraded = registerUser(store, {
    name: 'Social User',
    email: 'social@example.com',
    password: 'SenhaNova123',
  })
  assert.ok(upgraded.authProviders.includes('password'))
  assert.ok(upgraded.authProviders.includes('google'))

  const localSession = loginUser(store, { email: 'social@example.com', password: 'SenhaNova123' }, secret)
  assert.equal(localSession.provider, 'password')
})

test('providers status reflects oauth configuration', () => {
  const config = createOAuthConfig({
    baseUrl: 'http://localhost:3000',
    google: { clientId: 'google-client' },
  })

  const status = providersStatus(config)
  assert.equal(status.google.enabled, true)
  assert.equal(status.github.enabled, false)
  assert.ok(status.google.callbackUrl.includes('/auth/social/google/callback'))
})
