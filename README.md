# secure-auth-template

![CI](https://github.com/Beckerr11/secure-auth-template/actions/workflows/ci.yml/badge.svg)

Template de autenticacao segura.

## Objetivo
Este repositorio faz parte de uma trilha de portfolio profissional full stack, com foco em simplicidade, clareza e boas praticas.

## Stack
Node.js, JWT custom, OAuth-ready social login

## Funcionalidades implementadas
- Cadastro/login com senha e refresh token
- Fluxo social OAuth-ready com state
- Upgrade de conta social para senha local
- Reset de senha e endpoint /auth/me

## Como executar
~~~bash
npm ci
npm test
npm run dev
~~~

## Scripts uteis
- npm run dev, npm test

## Qualidade
- CI em .github/workflows/ci.yml
- Dependabot em .github/dependabot.yml
- Testes locais obrigatorios antes de merge

## Documentacao
- [Guia de deploy](docs/DEPLOY.md)
- [Roadmap](docs/ROADMAP.md)
- [Checklist de producao](docs/PRODUCTION-CHECKLIST.md)
- [Contribuicao](CONTRIBUTING.md)
- [Seguranca](SECURITY.md)

## Status
- [x] Scaffold inicial
- [x] Base funcional com testes
- [ ] Deploy publico com observabilidade completa
- [ ] Versao 1.0.0 com demo publica

