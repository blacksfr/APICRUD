import { describe, test, expect, beforeAll, afterAll, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app/app.js';
import UserRepository from '../src/repositories/user.repository.js';
import { isProd } from '../src/config/env.js';

// =========================================================================
// 0. CONFIGURAÇÃO DE MOCKS (VITEST)
// =========================================================================

vi.mock('../src/repositories/user.repository.js', () => ({
  default: {
    findForLogin: vi.fn(),
    create: vi.fn(),
    findById: vi.fn(),
    updateById: vi.fn(),
    deleteById: vi.fn(),
    exists: vi.fn(),
  }
}));

vi.mock('../src/connections/mongodb.connection.js', () => ({
  default: {
    getConnection: vi.fn(() => ({
      collection: vi.fn(() => ({
        deleteMany: vi.fn().mockResolvedValue({}),
        findOne: vi.fn(),
      }))
    })),
    killConnection: vi.fn().mockResolvedValue(true),
  }
}));

describe('Enterprise Security & Vulnerability Test Suite (MOCKED)', () => {
    let agent;
    let csrfToken;
    let userAId = '65f1a2b3c4d5e6f7a8b9c0d1';
    let userBId = '65f1a2b3c4d5e6f7a8b9c0d2';
    let userAToken, userBToken;

    const extractToken = (res) => res.body.csrfToken ?? csrfToken;

    beforeAll(async () => {
        agent = request.agent(app);
        const res = await agent.get('/');
        csrfToken = res.body.csrfToken || 'mock-csrf-token';
    });

    beforeEach(() => {
        vi.clearAllMocks();
    });

    // =========================================================================
    // 1. JWT & IDENTITY INTEGRITY
    // =========================================================================

    test('IAM: Registro e Gestão de JWT', async () => {
        UserRepository.create.mockResolvedValueOnce({ id: userAId, username: 'user_alpha' });
        const resA = await agent.post('/users')
            .set('x-csrf-token', csrfToken)
            .send({ username: 'user_alpha', password: 'StrongPassword123!' });
        
        expect(resA.status).toBe(201);
        userAToken = resA.body.accessToken;
        csrfToken = extractToken(resA);

        UserRepository.create.mockResolvedValueOnce({ id: userBId, username: 'user_beta' });
        const resB = await agent.post('/users')
            .set('x-csrf-token', csrfToken)
            .send({ username: 'user_beta', password: 'AnotherPassword456!' });
        
        expect(resB.status).toBe(201);
        userBToken = resB.body.accessToken;
    });

    // =========================================================================
    // 2. OWASP TOP 10: BOLA (A01:2021)
    // =========================================================================

    test('OWASP BOLA: Usuário B não pode acessar perfil do Usuário A', async () => {
        UserRepository.findById.mockResolvedValueOnce({ id: userAId, username: 'user_alpha' });
        const response = await agent.get(`/users/${userAId}`)
            .set('Authorization', `Bearer ${userBToken}`)
            .set('x-csrf-token', csrfToken);
        
        expect(response.status).toBe(403);
    });

    // =========================================================================
    // 3. INPUT VALIDATION & INTEGRITY
    // =========================================================================

    test('Injection: NoSQL Filter Bypass no Login', async () => {
        const response = await agent.post('/users/login')
            .set('x-csrf-token', csrfToken)
            .send({ username: { "$gt": "" }, password: "123" });
        
        expect(response.status).toBe(400);
        expect(UserRepository.findForLogin).not.toHaveBeenCalled();
    });

    test('Mass Assignment: Bloqueio de campos sensíveis (role)', async () => {
        const res = await agent.post('/users')
            .set('x-csrf-token', csrfToken)
            .send({ 
                username: 'admin_wannabe', 
                password: 'Password123!',
                role: 'admin'
            });
        expect(res.status).toBe(400); 
        expect(UserRepository.create).not.toHaveBeenCalled();
    });

    // =========================================================================
    // 4. INFRASTRUCTURE & SECURE HEADERS (A05:2021)
    // =========================================================================

    test('A05: Misconfiguration - Headers de segurança (Helmet)', async () => {
        const res = await agent.get('/');
        expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        
        if (isProd) {
            expect(res.headers['strict-transport-security']).toBeDefined();
        } else {
            expect(res.headers['strict-transport-security']).toBeUndefined();
        }
    });

    test('A01: CSRF - Deve rejeitar requisições de alteração sem token válido', async () => {
        const res = await request(app)
            .put(`/users/${userAId}`)
            .send({ username: 'attacker_name' });

        expect(res.status).toBe(403);
    });

    // =========================================================================
    // 5. AVAILABILITY & ANTI-DoS
    // =========================================================================

    test('A04: Anti-DoS - Deve rejeitar payloads maiores que 1MB', async () => {
        const bigData = 'a'.repeat(1024 * 1024 * 1.1); 
        const res = await agent.post('/users')
            .set('x-csrf-token', csrfToken)
            .send({ username: 'big_user', password: bigData });

        expect(res.status).toBe(413);
    });

    test('Rate Limit: Registro Excedido (registerLimiter)', async () => {
        for (let i = 0; i < 4; i++) {
            await agent.post('/users').set('x-csrf-token', csrfToken).send({ username: `u${i}`, password: 'P1!' });
        }
        const resLimit = await agent.post('/users')
            .set('x-csrf-token', csrfToken)
            .send({ username: 'user_limit', password: 'Password123!' });
        
        expect(resLimit.status).toBe(429);
    });

    // NOVO TESTE DE BRUTE FORCE
    test('Rate Limit: Login Brute Force (loginLimiter)', async () => {
        const loginData = { username: 'user_alpha', password: 'wrong_password' };
        for (let i = 0; i < 5; i++) {
            await agent.post('/users/login')
                .set('x-csrf-token', csrfToken)
                .send(loginData);
        }
        
        const blockedRes = await agent.post('/users/login')
            .set('x-csrf-token', csrfToken)
            .send(loginData);
            
        expect(blockedRes.status).toBe(429);
    });

    afterAll(async () => {
        vi.restoreAllMocks();
    });
});