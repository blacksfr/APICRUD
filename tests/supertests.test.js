import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import app from '../src/app/app.js';
import MongoDBConnection from '../src/connections/mongodb.connection.js';

describe('Enterprise Security & Vulnerability Test Suite (Full JWT & Route-Based Limits)', () => {
    let db;
    let agent;
    let csrfToken;
    let userAId, userBId, userAToken, userBToken;

    const extractToken = (res) => {
        const cookies = res.headers['set-cookie'] || [];
        const tokenCookie = cookies.find(c => c.startsWith('X-CSRF-Token'));
        if (tokenCookie) {
            return decodeURIComponent(tokenCookie.split('=')[1].split(';')[0]);
        }
        return csrfToken;
    };

    beforeAll(async () => {
        db = await MongoDBConnection.getConnection();
        await db.collection('users').deleteMany({
            username: { $in: ['user_alpha', 'user_beta', 'mass_assign', 'admin_wannabe', 'user_4', 'big_user'] }
        });

        agent = request.agent(app);
        const res = await agent.get('/'); // Acorda o CSRF
        csrfToken = extractToken(res);
    });

    // =========================================================================
    // 1. JWT & IDENTITY INTEGRITY
    // =========================================================================

    test('IAM: Registro e Gestão de JWT', async () => {
        const resA = await agent.post('/users')
            .set('X-CSRF-Token', csrfToken)
            .send({ username: 'user_alpha', password: 'StrongPassword123!' });
        
        expect(resA.status).toBe(201);
        userAId = resA.body.user.id;
        userAToken = resA.body.accessToken;
        csrfToken = extractToken(resA);

        const resB = await agent.post('/users')
            .set('X-CSRF-Token', csrfToken)
            .send({ username: 'user_beta', password: 'AnotherPassword456!' });
        
        expect(resB.status).toBe(201);
        userBId = resB.body.user.id;
        userBToken = resB.body.accessToken;
        csrfToken = extractToken(resB);
    });

    test('JWT: Deve rejeitar acesso sem token em rota protegida', async () => {
        const res = await agent.get(`/users/${userAId}`)
            .set('X-CSRF-Token', csrfToken);
        
        expect(res.status).toBe(401);
    });

    test('JWT: Deve rejeitar token com assinatura forjada', async () => {
        const forgedToken = userAToken.substring(0, userAToken.length - 10) + "abcdefghij";
        const res = await agent.get(`/users/${userAId}`)
            .set('Authorization', `Bearer ${forgedToken}`)
            .set('X-CSRF-Token', csrfToken);
        
        expect(res.status).toBe(403); 
    });

    // =========================================================================
    // 2. OWASP TOP 10: BOLA (A01:2021)
    // =========================================================================

    test('OWASP BOLA: Usuário B não pode acessar perfil do Usuário A', async () => {
        const response = await agent.get(`/users/${userAId}`)
            .set('Authorization', `Bearer ${userBToken}`)
            .set('X-CSRF-Token', csrfToken);
        
        expect(response.status).toBe(403);
    });

    // =========================================================================
    // 3. INPUT VALIDATION & INTEGRITY (A03:2021)
    // =========================================================================

    test('Injection: NoSQL Filter Bypass no Login', async () => {
        const response = await agent.post('/users/login')
            .set('X-CSRF-Token', csrfToken)
            .send({ username: { "$gt": "" }, password: "123" });
        
        csrfToken = extractToken(response);
        expect(response.status).toBe(400); 
    });

    test('Mass Assignment: Bloqueio de campos sensíveis (role)', async () => {
        const res = await agent.post('/users')
            .set('X-CSRF-Token', csrfToken)
            .send({ 
                username: 'admin_wannabe', 
                password: 'Password123!',
                role: 'admin' 
            });
        
        csrfToken = extractToken(res);
        const userInDb = await db.collection('users').findOne({ username: 'admin_wannabe' });
        expect(userInDb?.role).toBeUndefined();
    });

    // =========================================================================
    // 4. INFRASTRUCTURE & SECURE HEADERS (A05:2021)
    // =========================================================================

    test('A05: Misconfiguration - Headers de segurança (Helmet/Lusca)', async () => {
        const res = await agent.get('/');
        expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        expect(res.headers['strict-transport-security']).toBeDefined();
    });

    test('A01: CSRF - Deve rejeitar requisições de alteração sem token válido', async () => {
        // Usando request(app) sem o agent para simular uma requisição sem cookies/sessão de token
        const res = await request(app)
            .put(`/users/${userAId}`)
            .send({ username: 'attacker', password: 'Password123!' });

        expect(res.status).toBe(403);
        expect(res.body.message).toBe("Form tampered with or invalid CSRF token");
    });

    // =========================================================================
    // 5. AVAILABILITY & ANTI-DoS (A04:2021)
    // =========================================================================

    test('A04: Anti-DoS - Deve rejeitar payloads maiores que 1MB', async () => {
        const bigData = "a".repeat(1024 * 1024 * 1.1); // 1.1MB
        const res = await agent.post('/users')
            .set('X-CSRF-Token', csrfToken)
            .send({ username: 'big_user', password: bigData });

        csrfToken = extractToken(res);
        expect(res.status).toBe(413);
        expect(res.body.error).toBe("PAYLOAD_TOO_LARGE");
    });

    test('Rate Limit: Registro Excedido (registerLimiter)', async () => {
        const res4 = await agent.post('/users')
            .set('X-CSRF-Token', csrfToken)
            .send({ username: 'user_5', password: 'Password123!' });
        csrfToken = extractToken(res4);

        const res5 = await agent.post('/users')
            .set('X-CSRF-Token', csrfToken)
            .send({ username: 'user_6', password: 'Password123!' });
        
        expect(res5.status).toBe(429);
        expect(res5.body.error).toBe("Too many registration attempts");
    });

    test('Rate Limit: Login Brute Force (loginLimiter)', async () => {
        const loginData = { username: 'user_alpha', password: 'wrong_password' };
        
        for (let i = 0; i < 5; i++) {
            const res = await agent.post('/users/login')
                .set('X-CSRF-Token', csrfToken)
                .send(loginData);
            csrfToken = extractToken(res);
        }
        
        const blockedRes = await agent.post('/users/login')
            .set('X-CSRF-Token', csrfToken)
            .send(loginData);
            
        expect(blockedRes.status).toBe(429);
        expect(blockedRes.body.error).toBe("Too many login attempts");
    });

    afterAll(async () => {
        if (db) {
            await db.collection('users').deleteMany({
                username: { $in: ['user_alpha', 'user_beta', 'mass_assign', 'admin_wannabe', 'user_4', 'big_user'] }
            });
            await MongoDBConnection.killConnection();
        }
    });
});