import { createApp, createOAuthConfig, createStore } from '../src/app.js'

const store = globalThis.__secureAuthStore || (globalThis.__secureAuthStore = createStore())
const oauthConfig = createOAuthConfig()
const jwtSecret = process.env.JWT_SECRET || 'dev-secret'

const app = createApp(store, jwtSecret, { oauthConfig })

export default app
