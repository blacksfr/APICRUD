import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import app from '../app/app.js';
import MongoDBConnection from '../connections/MongoDBConnection.js';

describe('Enterprise Security & Vulnerability Test Suite', () => {
    let userAToken, userBToken, userAId, userBId;
    let db;

    /**
     * @lifecycle Pre-test Database Scrubbing
     * Garante a idempotência dos testes removendo resquícios de execuções anteriores.
     */
    beforeAll(async () => {
        db = await MongoDBConnection.getConnection();
        await db.collection('users').deleteMany({
            username: { $in: ['user_alpha', 'user_beta', 'attacker_xss', 'mass_assign', 'big_user', 'overflow'] }
        });
    });

    // =========================================================================
    // 1. IDENTITY & ACCESS MANAGEMENT (IAM)
    // =========================================================================
    
    test('IAM: Registro e Integridade de Identidade', async () => {
        // Valida o fluxo positivo de criação e a restrição de unicidade (CWE-290)
        const userData = { username: 'user_alpha', password: 'StrongPassword123!' };
        const resA = await request(app).post('/users').send(userData);
        expect(resA.status).toBe(201);
        userAId = resA.body.user.id;
        userAToken = resA.body.accessToken;

        const resConflict = await request(app).post('/users').send(userData);
        expect(resConflict.status).toBe(409); // Conflict: Previne duplicação de identidade

        const resB = await request(app).post('/users').send({
            username: 'user_beta',
            password: 'AnotherPassword456!'
        });
        userBId = resB.body.user.id;
        userBToken = resB.body.accessToken;
    });

    // =========================================================================
    // 2. INPUT VALIDATION & SANITIZATION (OWASP A03:2021)
    // =========================================================================

    test('Injection: NoSQL Filter Bypass Mitigation', async () => {
        // Testa se o parser impede objetos de query em campos de login (Prevention of $gt/$ne injection)
        const response = await request(app)
            .post('/users/login')
            .send({ username: { "$gt": "" }, password: "123" });
        expect(response.status).toBe(400); 
    });

    test('XSS: Content Sanitization (Stored/Reflected)', async () => {
        // Garante que tags <script> sejam barradas ou sanitizadas pelo Zod/Validator
        const response = await request(app)
            .post('/users')
            .send({
                username: '<script>alert("xss")</script>',
                password: 'StrongPassword123!'
            });
        expect(response.status).toBe(400);
    });

    test('Broken Object Level Authorization (BOLA/IDOR): Cross-User Access', async () => {
        // Testa a falha de Broken Object Level Authorization (OWASP A01:2021)
        // O usuário A jamais deve acessar recursos privados do usuário B
        const resGet = await request(app)
            .get(`/users/${userBId}`)
            .set('Authorization', `Bearer ${userAToken}`);
        expect(resGet.status).toBe(403);
    });

    // =========================================================================
    // 3. SECURE INFRASTRUCTURE & HEADERS (OWASP A05:2021)
    // =========================================================================

    test('Infra: Hardening de Headers via Helmet.js', async () => {
        // Verifica a implementação de políticas de segurança no transporte e renderização
        const response = await request(app).get('/');
        expect(response.headers['x-content-type-options']).toBe('nosniff'); // Previne MIME sniffing
        expect(response.headers['strict-transport-security']).toBeDefined(); // Força HTTPS (HSTS)
        expect(response.headers['x-frame-options']).toBeDefined(); // Previne Clickjacking
    });

    test('Anti-DoS: Controle de Tamanho de Payload', async () => {
        // Mitigação de negação de serviço por exaustão de memória (CWE-400)
        const bigData = "a".repeat(1024 * 1024 * 1.2); // 1.2MB
        const response = await request(app)
            .post('/users')
            .send({ username: 'overflow', password: bigData });
        expect(response.status).toBe(413); // Payload Too Large
    });

    // =========================================================================
    // 4. AUTHENTICATION & CRYPTOGRAPHY (OWASP A02:2021)
    // =========================================================================

    test('Auth: Integridade de Assinatura JWT', async () => {
        // Garante que o servidor rejeita tokens com assinaturas manipuladas ou malformadas
        const response = await request(app)
            .get(`/users/${userAId}`)
            .set('Authorization', `Bearer token.invalido.123`);
        expect([401, 403]).toContain(response.status);
    });

    // =========================================================================
    // 5. AVAILABILITY & ANTI-ABUSE (RATE LIMITING)
    // =========================================================================

    test('Anti-Brute Force: Mecanismo de Bloqueio Exponencial', async () => {
        // Valida se o middleware de Rate Limit bloqueia tentativas de força bruta no login
        const loginData = { username: 'user_alpha', password: 'wrong_password' };
        for (let i = 0; i < 5; i++) {
            await request(app).post('/users/login').send(loginData);
        }
        const blockedRes = await request(app).post('/users/login').send(loginData);
        expect(blockedRes.status).toBe(429); // Too Many Requests
    });

    test('Global Rate Limit: Resiliência contra Stress/DoS', async () => {
        /** * @strategy Burst-Testing
         * Dispara requisições paralelas para testar o teto de 300 requisições da rota principal.
         */
        let blocked = false;
        const batchSize = 50; 
        const totalRequests = 350; 

        for (let i = 0; i < totalRequests; i += batchSize) {
            const promises = Array.from({ length: batchSize }).map(() => request(app).get('/'));
            const responses = await Promise.all(promises);
            if (responses.some(res => res.status === 429)) {
                blocked = true;
                break;
            }
        }
        expect(blocked).toBe(true);
    }, 20000); 

    /**
     * @lifecycle Teardown
     * Garante o encerramento limpo das conexões para evitar memory leaks no CI/CD.
     */
    afterAll(async () => {
        if (db) {
            await db.collection('users').deleteMany({
                username: { $in: ['user_alpha', 'user_beta', 'attacker_xss', 'mass_assign', 'big_user', 'overflow'] }
            });
            await MongoDBConnection.killConnection();
        }
    });
});