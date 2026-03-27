import test from 'node:test'
import assert from 'node:assert/strict'
import { createStore, registerUser, loginUser, requestPasswordReset, resetPassword } from '../src/app.js'

test('register, login and password reset flow', () => {
  const store = createStore()
  const secret = 'secret-test'

  registerUser(store, { name: 'Douglas', email: 'douglas@example.com', password: 'SenhaSegura123' })

  const login = loginUser(store, { email: 'douglas@example.com', password: 'SenhaSegura123' }, secret)
  assert.ok(login.token)

  const reset = requestPasswordReset(store, { email: 'douglas@example.com' })
  assert.ok(reset.token)

  const result = resetPassword(store, { token: reset.token, newPassword: 'NovaSenha1234' })
  assert.equal(result.message, 'senha atualizada com sucesso')

  const relogin = loginUser(store, { email: 'douglas@example.com', password: 'NovaSenha1234' }, secret)
  assert.ok(relogin.token)
})