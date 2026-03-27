import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createStore,
  registerUser,
  loginUser,
  refreshSession,
  authMe,
  requestPasswordReset,
  resetPassword,
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