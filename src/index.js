import http from 'node:http'

const port = Number(process.env.PORT || 3000)

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, service: 'secure-auth-template' }))
    return
  }

  res.writeHead(200, { 'content-type': 'application/json' })
  res.end(JSON.stringify({ message: 'Scaffold inicial de secure-auth-template' }))
})

server.listen(port, () => {
  console.log('secure-auth-template running on port ' + port)
})