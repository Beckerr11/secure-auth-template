import http from 'node:http'
import { createApp, createStore } from './app.js'

const port = Number(process.env.PORT || 3000)
const app = createApp(createStore())

http.createServer(app).listen(port, () => {
  console.log(`secure-auth-template running on port ${port}`)
})