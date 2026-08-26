# Secure Auth Template

![CI](https://github.com/Beckerr11/secure-auth-template/actions/workflows/ci.yml/badge.svg)

Referência pequena de autenticação em **Node.js**, focada em tornar explícitos os estados de uma sessão: cadastro, senha com hash, token de acesso assinado, refresh token, reset de senha e preparação de fluxo social.

O projeto usa armazenamento em memória de propósito. Ele serve para estudar contratos e testes de autenticação sem esconder a lógica atrás de um framework ou serviço externo.

## O que está implementado

- cadastro com normalização de e-mail e senha mínima;
- hash de senha com `scrypt` + salt aleatório;
- login por senha;
- access token assinado com HMAC e expiração;
- refresh tokens com expiração e estado de revogação;
- endpoint autenticado `/auth/me`;
- solicitação e consumo de token de reset de senha;
- upgrade de uma conta social para login local por senha;
- geração e consumo de `state` para Google/GitHub;
- construção da authorize URL dos provedores sociais;
- status de configuração dos providers;
- limite de 1 MB para payload JSON.

## O que não é

Este repositório **não é uma biblioteca de autenticação pronta para produção**.

Em especial:

- o token de acesso é um formato HMAC didático próprio, não um JWT padrão;
- usuários, refresh tokens, reset tokens e OAuth states ficam em memória;
- o callback social não faz o exchange real do authorization code nem consulta a identidade no Google/GitHub;
- não existe envio real de e-mail para reset;
- existe um secret de desenvolvimento como fallback quando `JWT_SECRET` não é informado.

Esses limites são deliberados e deixam claro o que ainda precisaria mudar antes de produção.

## Arquitetura

```text
HTTP request
    ↓
Node HTTP application
    ↓
validation + auth state machine
    ├── password / scrypt
    ├── signed access token
    ├── refresh token store
    ├── password-reset store
    └── OAuth state + provider configuration
    ↓
in-memory store
```

## Executando

```bash
npm ci
npm test
npm run dev
```

Variáveis opcionais para experimentar o fluxo social:

```env
JWT_SECRET=troque-este-valor
APP_BASE_URL=http://localhost:3000
GOOGLE_CLIENT_ID=
GITHUB_CLIENT_ID=
```

Client secrets não fazem parte do fluxo implementado atualmente porque o projeto ainda não realiza o token exchange do OAuth.

## Qualidade

- testes com o test runner nativo do Node.js;
- CI em GitHub Actions;
- Dependabot;
- documentação de deploy, produção e segurança no diretório `docs/` e em `SECURITY.md`.

## Evolução natural

Para transformar esta referência em um serviço de autenticação real seria necessário, entre outros pontos:

- persistência transacional;
- rotação/revogação robusta de refresh tokens;
- cookies seguros ou estratégia equivalente;
- CSRF conforme o modelo de sessão adotado;
- exchange OAuth real e validação da identidade no provedor;
- entrega de e-mail;
- gestão de secrets;
- rate limiting e observabilidade;
- auditoria de sessão e eventos de segurança.

## Autor

**Douglas Silva**  
[GitHub](https://github.com/Beckerr11) · [Portfólio](https://douglasdev.tech)
