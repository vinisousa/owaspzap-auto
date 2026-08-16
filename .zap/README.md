# OWASP ZAP – Scan autenticado (workflow + planos)

Workflow: `.github/workflows/owasp-zap-scan.yml` (disparo manual via **Run workflow**).
Executa dois jobs independentes, usando a imagem oficial `ghcr.io/zaproxy/zaproxy:stable`
e planos do ZAP Automation Framework em `.zap/plans/`:

- **web-scan**: login autenticado (form-based) + spider + spider AJAX + active scan da área logada.
- **api-scan**: importa a spec OpenAPI, injeta um header de autenticação em todas as requisições
  (token/API key) e roda o active scan sobre a API.

Nenhuma credencial fica no código: os arquivos `.zap/plans/*.yaml.tmpl` são apenas templates
(`${VAR}`) preenchidos em tempo de execução, dentro do runner, via `envsubst`, usando variáveis
de ambiente vindas de **Secrets** e **Variables** do GitHub Actions.

## Configuração necessária (Settings → Secrets and variables → Actions)

### Variables (não sensíveis)

| Nome | Obrigatório | Descrição |
|---|---|---|
| `ZAP_TARGET_URL` | sim (web) | URL base da aplicação a ser escaneada |
| `ZAP_LOGIN_URL` | sim (web) | URL da página de login |
| `ZAP_LOGIN_REQUEST_URL` | sim (web) | URL para onde o formulário de login envia o POST |
| `ZAP_LOGIN_USERNAME_FIELD` | não (default `username`) | Nome do campo de usuário no form |
| `ZAP_LOGIN_PASSWORD_FIELD` | não (default `password`) | Nome do campo de senha no form |
| `ZAP_LOGGED_IN_INDICATOR` | sim (web) | Regex presente na resposta quando o login é bem-sucedido (ex.: `Logout`) |
| `ZAP_LOGGED_OUT_INDICATOR` | não | Regex presente quando a sessão está deslogada |
| `ZAP_SPIDER_MAX_DURATION` | não (default `5`) | Minutos máx. do spider tradicional |
| `ZAP_AJAX_SPIDER_MAX_DURATION` | não (default `5`) | Minutos máx. do spider AJAX |
| `ZAP_ACTIVE_SCAN_MAX_DURATION` | não (default `30`) | Minutos máx. do active scan (web) |
| `ZAP_API_TARGET_URL` | sim (api) | URL base da API |
| `ZAP_OPENAPI_URL` | sim (api) | URL da definição OpenAPI/Swagger |
| `ZAP_API_AUTH_HEADER_NAME` | não (default `Authorization`) | Nome do header de autenticação da API |
| `ZAP_API_ACTIVE_SCAN_MAX_DURATION` | não (default `30`) | Minutos máx. do active scan (api) |
| `ZAP_BOLA_TARGETS` | não | JSON com os endpoints/IDs pra testar BOLA de verdade (ver seção do probe abaixo). |

### Secrets (sensíveis)

| Nome | Obrigatório | Descrição |
|---|---|---|
| `ZAP_LOGIN_USERNAME` | sim (web) | Usuário para autenticação na área logada |
| `ZAP_LOGIN_PASSWORD` | sim (web) | Senha para autenticação na área logada |
| `ZAP_API_AUTH_HEADER_VALUE` | sim (api) | Valor completo do header de auth da API, ex.: `Bearer <token>` |
| `ZAP_API_AUTH_HEADER_VALUE_LOWPRIV` | não | Header já pronto (`Bearer <token>`) de um usuário **menos privilegiado**, usado pelo probe de BFLA. Ignorado se `ZAP_LOWPRIV_USERNAME`/`ZAP_LOWPRIV_PASSWORD` estiverem configurados (preferível, já que um token estático expira). |
| `ZAP_LOWPRIV_USERNAME` | não | Usuário/e-mail de uma conta **menos privilegiada** (Conta A) — o workflow faz login sozinho no endpoint de login da API pra gerar um token fresco a cada execução. |
| `ZAP_LOWPRIV_PASSWORD` | não | Senha da conta acima. |
| `ZAP_LOWPRIV2_USERNAME` | não | Usuário/e-mail de uma **segunda** conta menos privilegiada (Conta B), só necessária pro probe de BOLA. |
| `ZAP_LOWPRIV2_PASSWORD` | não | Senha da conta acima. |

## Resultado

Os relatórios (HTML, JSON e XML) ficam disponíveis como artifacts do workflow
(`zap-full-scan-reports` e `zap-api-scan-reports`). O step "Evaluate scan result" de cada
job usa um exit code próprio: `0` = sem alertas High/Medium, `1` = o scan não completou
(falha de execução), `2` = achou alerta **High**, `3` = achou alerta **Medium** (sem High).
O job falha (vermelho no Actions) em qualquer código diferente de 0, mas o motivo real —
"achou vulnerabilidade" vs. "o scan travou" — sempre fica explícito no log e nos outputs
`high_alert_count`/`medium_alert_count`/`high_alerts_found` do step.

### Probe de BFLA / BOPLA / BOLA (job `api-scan`)

O Automation Framework do ZAP não tem job nativo para os addons **Access Control Testing**
(BOLA/BFLA) nem **Fuzzer** (BOPLA) — ambos exigem rodar o ZAP como daemon e pilotar a API
Java/Python dele, ou (no caso do Access Control) uma matriz de acesso curada manualmente por
URL. Em vez disso, o job `api-scan` roda um step extra, `.zap/scripts/api_authz_probe.py`
(sem dependências externas, só stdlib), que faz três checks heurísticos direto contra a spec
OpenAPI:

- **BFLA (OWASP API5)**: repete todo endpoint da spec com a credencial de baixo privilégio (Conta A,
  `ZAP_LOWPRIV_USERNAME`/`ZAP_LOWPRIV_PASSWORD`, logada automaticamente pelo `.zap/scripts/mint_api_token.py`,
  ou o `ZAP_API_AUTH_HEADER_VALUE_LOWPRIV` estático) e sinaliza qualquer um que responda 2xx —
  especialmente em métodos de escrita (POST/PUT/PATCH/DELETE).
- **BOPLA (OWASP API3)**: para endpoints de escrita com corpo JSON, monta um payload a partir do
  schema declarado e adiciona propriedades **fora** do schema (`role`, `isAdmin`, `permissions`,
  `balance`, etc.); sinaliza se a API aceitar (e mais ainda se ecoar a propriedade de volta).
- **BOLA (OWASP API1)**: só roda se `ZAP_BOLA_TARGETS` estiver configurado — é o único dos três
  que precisa de input manual, porque exige saber qual ID de recurso pertence a qual conta (isso
  não dá pra inferir da spec). Formato (JSON, uma entrada por endpoint parametrizado):
  ```json
  [
    {
      "path": "/api/virtual-cards/{card_id}/update-limit",
      "method": "POST",
      "id_param": "card_id",
      "id_a": "1",
      "id_b": "2"
    }
  ]
  ```
  `id_a` precisa pertencer à Conta A (`ZAP_LOWPRIV_USERNAME`) e `id_b` à Conta B
  (`ZAP_LOWPRIV2_USERNAME`/`ZAP_LOWPRIV2_PASSWORD`). O probe testa nos dois sentidos: Conta A
  acessando o objeto `id_b` da Conta B, e Conta B acessando o objeto `id_a` da Conta A — qualquer
  2xx nesse acesso cruzado é sinalizado como **high**, já que aqui não é heurística: é acesso
  comprovado ao recurso de outra conta.

O resultado vira o artifact `zap-authz-probe-report` (JSON + Markdown) e aparece como
`::warning::` no log — **nunca falha o job sozinho**, porque BFLA/BOPLA são heurísticos sujeitos
a falso positivo (ex.: um endpoint público de propósito também aparece como "achado" de BFLA).
Cada achado precisa de revisão humana antes de virar um bug real (o BOLA é o mais confiável dos
três, já que usa contas e objetos reais em vez de heurística).

`mint_api_token.py` acha o endpoint de login sozinho (procura na spec um path com `post` cujo
nome contenha "login"/"auth"/"signin"), mapeia os campos do schema (`email`/`username` e
`password`) e procura um token na resposta (top-level ou um nível aninhado, testando nomes
comuns como `token`, `access_token`, `jwt`). Se não achar, só loga as **chaves** da resposta
(nunca os valores) e pula os probes que dependem dele sem quebrar o job — dá pra ver esse aviso
no log dos steps "Mint low-privileged API token" e ajustar se o formato da API for diferente do
esperado.

## Observações

- Ajuste `.zap/plans/full-scan.yaml.tmpl` e `.zap/plans/api-scan.yaml.tmpl` se o app usar
  autenticação diferente de form-based (ex.: JSON, script, OAuth) — o ZAP Automation Framework
  suporta outros métodos em `authentication.method`.
- Para reaproveitar a sessão web autenticada na API (em vez de header estático), é possível
  compartilhar o mesmo `context`/`user` do job `web-scan` no plano de API.
