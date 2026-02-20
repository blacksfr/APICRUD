# APICRUD: Enterprise User Management API (Security-First)

API REST de Usuários com foco em **Segurança Enterprise** e **OWASP Top 10**. Desenvolvida em Node.js e MongoDB, utiliza Zod para validação estrita e Vitest para testes automatizados.

## Descrição
Este projeto implementa um sistema robusto de gestão de usuários, priorizando a mitigação de vulnerabilidades modernas como **Anti-Mass Assignment**, **NoSQL Injection** e **IDOR/BOLA**. A arquitetura foi desenhada para ser escalável e seguir o princípio de *fail-fast validation*.

## Tecnologias e Ferramentas
* **Runtime:** Node.js (ESM)
* **Framework:** Express.js 5.x
* **Banco de Dados:** MongoDB (Driver Nativo)
* **Segurança:** Helmet, Express-Rate-Limit, Bcrypt, Crypto (CSPRNG)
* **Validação/Schema:** Zod (Strict Mode)
* **Testes:** Vitest & Supertest

## Diferenciais de Segurança (OWASP Focused)
Este projeto foi construído para mitigar as vulnerabilidades mais comuns do mercado:

* **Broken Object Level Authorization (BOLA/IDOR):** Validação rigorosa de propriedade de recursos em rotas de ID.
* **Mass Assignment Protection:** Uso de `.strict()` no Zod e camadas de repositório que filtram campos sensíveis (`isAdmin`, `role`) antes da persistência.
* **CSPRNG Password Security:** Gerador de senhas com alta entropia e cálculo de bits de força para prevenir senhas fracas.
* **NoSQL Injection Defense:** Sanitização automática via Schema e tipagem forte.
* **Rate Limiting Granular:** Limitadores específicos para Login, Registro e Ações de Usuário, protegendo contra Brute Force e DoS.
* **Pre-Hashing Strategy:** Uso de SHA-256 antes do Bcrypt para contornar o limite de 72 caracteres do algoritmo e aumentar a segurança.



## Arquitetura
O projeto segue o padrão de **Clean Architecture** simplificado para garantir separação de responsabilidades:
1.  **Routers:** Definição de rotas e aplicação de Middlewares de proteção.
2.  **Controllers:** Orquestração da lógica de entrada e resposta.
3.  **Repositories:** Camada de abstração de dados (BaseRepository) com sanitização de saída automática.
4.  **Schemas (Zod):** Única fonte de verdade para a estrutura de dados (Input/Output).



## Boas Práticas Implementadas
* **Isolamento de Output (`BaseRepository.js`):** Uso de `#sanitizePublic` para garantir que campos sensíveis nunca cheguem ao cliente.
* **Validação Estrita (`UserSchema.js`):** Bloqueio de campos desconhecidos em requisições.
* **Cálculo de Entropia:** Validação de força de senha baseada em bits de entropia (mín. 64 bits).
* **Rate Limit por Função:** Limites independentes para `login`, `register` e `refresh` para evitar abusos sem prejudicar a UX.
* **Segurança de Headers:** Uso de Helmet.js e remoção de headers de identificação de tecnologia (`x-powered-by`).

---
 *Documentação gerada com auxílio de IA para auditoria de segurança.*