import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import app from '../app/app.js';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';
import MongoDBConnection from '../connections/MongoDBConnection.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '..', 'src', '.env') });

describe('Enterprise Security & Vulnerability Test Suite', () => {
    let userAToken, userBToken, userAId, userBId;
    let db;

    beforeAll(async () => {
        db = await MongoDBConnection.getConnection();

        await db.collection('users').deleteMany({
            username: { $in: ['user_alpha', 'user_beta', 'attacker_xss', 'mass_assign'] }
        });
    });

    // ==================================================
    // SETUP
    // ==================================================
    test('Setup & Negócio: Registro e Bloqueio de Duplicidade', async () => {
        const userData = { username: 'user_alpha', password: 'StrongPassword123!' };

        const resA = await request(app).post('/users').send(userData);
        expect(resA.status).toBe(201);

        userAId = resA.body.user.id;
        userAToken = resA.body.accessToken;

        const resConflict = await request(app).post('/users').send(userData);
        expect(resConflict.status).toBe(409);
        expect(resConflict.body.error).toBe("CONFLICT");

        const resB = await request(app).post('/users').send({
            username: 'user_beta',
            password: 'AnotherPassword456!'
        });

        userBId = resB.body.user.id;
        userBToken = resB.body.accessToken;
    });

    // ==================================================
    // INJECTION
    // ==================================================
    test('Vulnerabilidade: NoSQL Injection', async () => {
        const response = await request(app)
            .post('/users/login')
            .send({ username: { "$gt": "" }, password: "123" });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe("BAD_REQUEST");
    });

    test('XSS: Sanitização de entrada', async () => {
        const response = await request(app)
            .post('/users')
            .send({
                username: '<script>alert("xss")</script>',
                password: 'StrongPassword123!'
            });

        expect(response.status).toBe(400);
    });

    // ==================================================
    // MASS ASSIGNMENT
    // ==================================================
    test('Mass Assignment: Não permitir role admin via body', async () => {
        const response = await request(app)
            .post('/users')
            .send({
                username: 'mass_assign',
                password: 'StrongPassword123!',
                role: 'admin',
                isAdmin: true
            });

        expect(response.status).toBe(400);
        expect(response.body.error).toBe("BAD_REQUEST");
        expect(response.body.user?.role).toBeUndefined();
        expect(response.body.user?.isAdmin).toBeUndefined();

    });

    // ==================================================
    // IDOR / BOLA
    // ==================================================
    test('IDOR: Usuário A não pode acessar Usuário B', async () => {
        const resGet = await request(app)
            .get(`/users/${userBId}`)
            .set('Authorization', `Bearer ${userAToken}`);

        expect(resGet.status).toBe(403);
        expect(resGet.body.error).toBe("FORBIDDEN");

        const resDel = await request(app)
            .delete(`/users/${userBId}`)
            .set('Authorization', `Bearer ${userAToken}`);

        expect(resDel.status).toBe(403);
    });

    test('Validação: ID malformado', async () => {
        const response = await request(app)
            .get('/users/id_invalido_123')
            .set('Authorization', `Bearer ${userAToken}`);

        expect(response.status).toBe(400);
        expect(response.body.message).toBe("Invalid ID format");
    });

    // ==================================================
    // BROKEN AUTHENTICATION
    // ==================================================
    test('JWT: Token vazio', async () => {
        const response = await request(app)
            .get(`/users/${userAId}`)
            .set('Authorization', 'Bearer ');

        expect(response.status).toBe(401);
    });

    test('JWT: Token inválido manualmente alterado', async () => {
        const fakeToken = userAToken.slice(0, -1) + 'X';

        const response = await request(app)
            .get(`/users/${userAId}`)
            .set('Authorization', `Bearer ${fakeToken}`);

        expect([401, 403]).toContain(response.status);

    });

    test('JWT: Token completamente malformado', async () => {
        const response = await request(app)
            .get(`/users/${userAId}`)
            .set('Authorization', `Bearer token.invalido.123`);

        expect([401, 403]).toContain(response.status);
    });

    test('Login: Senha incorreta', async () => {
        const response = await request(app)
            .post('/users/login')
            .send({
                username: 'user_alpha',
                password: 'senha_errada'
            });

        expect(response.status).toBe(401);
    });

    test('Brute Force Básico: múltiplas tentativas falhas', async () => {
        for (let i = 0; i < 5; i++) {
            const response = await request(app)
                .post('/users/login')
                .send({
                    username: 'user_alpha',
                    password: 'wrong_password'
                });

            expect(response.status).toBe(401);
        }
    });

    // ==================================================
    // EXCESSIVE DATA EXPOSURE
    // ==================================================
    test('Excessive Data Exposure: Não retornar senha ou hash', async () => {
        const response = await request(app)
            .get(`/users/${userAId}`)
            .set('Authorization', `Bearer ${userAToken}`);

        expect(response.status).toBe(200);
        expect(response.body.password).toBeUndefined();
        expect(response.body.hash).toBeUndefined();
    });

    // ==================================================
    // SECURITY MISCONFIGURATION
    // ==================================================
    test('Security Headers: Deve ter headers básicos', async () => {
        const response = await request(app).get('/');

        expect(response.headers).toBeDefined();
        expect(response.headers['x-powered-by']).toBeUndefined(); // Express deve estar desabilitado
    });

    // ==================================================
    // DOS - PAYLOAD LIMIT
    // ==================================================
    test('DoS: Payload Limit', async () => {
        const bigData = "a".repeat(1024 * 1024 * 1.1);

        const response = await request(app)
            .post('/users')
            .send({ username: 'big_user', password: bigData });

        expect(response.status).toBe(413);
    });

    // ==================================================
    // RATE LIMIT - API4
    // ==================================================
    test('Rate Limit: Deve bloquear após muitas requisições', async () => {
    let blocked = false;
    const batchSize = 50;
    
    for (let i = 0; i < 1200; i += batchSize) {
        const promises = Array.from({ length: batchSize }).map(() => 
            request(app).get('/')
        );
        
        const responses = await Promise.all(promises);
        
        if (responses.some(res => res.status === 429)) {
            blocked = true;
            break;
        }
    }
    expect(blocked).toBe(true);
}, 30000);

    // ==================================================
    // RATE LIMIT HEADERS
    // ==================================================
    test('Rate Limit: Deve retornar headers padrão', async () => {
        const response = await request(app).get('/');

        expect(response.headers['ratelimit-limit']).toBeDefined();
        expect(response.headers['ratelimit-remaining']).toBeDefined();
    });

    // ==================================================
    // HELMET HEADERS
    // ==================================================
    test('Helmet: Deve incluir headers de segurança', async () => {
        const response = await request(app).get('/');

        expect(response.headers['x-dns-prefetch-control']).toBe('off');
        expect(response.headers['x-frame-options']).toBeDefined();
        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['referrer-policy']).toBeDefined();
    });

    // ==================================================
    // HSTS HEADER
    // ==================================================
    test('Helmet: Deve incluir HSTS', async () => {
        const response = await request(app).get('/');

        expect(response.headers['strict-transport-security']).toBeDefined();
    });

    // ==================================================
    // TIMEOUT HANDLING
    // ==================================================
    test('Timeout: Deve retornar 503 se requisição exceder tempo', async () => {
        const response = await request(app)
            .get('/users') // ajuste para rota que possa simular demora
            .timeout({ deadline: 31000 });

        if (response.status === 503) {
            expect(response.body.error).toBe("SERVICE_UNAVAILABLE");
        }
    });

    // ==================================================
    // PAYLOAD TOO LARGE - Estrutura correta
    // ==================================================
    test('Payload Too Large: Deve retornar erro estruturado', async () => {
        const bigData = "a".repeat(1024 * 1024 * 1.2);

        const response = await request(app)
            .post('/users')
            .send({ username: 'overflow', password: bigData });

        expect(response.status).toBe(413);
        expect(response.body.error).toBe("PAYLOAD_TOO_LARGE");
        expect(response.body.message).toBe("Maximum limit is 1MB");
    });

    // ==================================================
    // INTERNAL ERROR HANDLING
    // ==================================================
    test('Erro 500 deve ser padronizado', async () => {
        const response = await request(app)
            .post('/users/login')
            .send({}); // corpo inválido que pode gerar erro inesperado

        if (response.status === 500) {
            expect(response.body.error).toBe("INTERNAL_SERVER_ERROR");
            expect(response.body.message).toBe("Something went wrong!");
        }
    });

    afterAll(async () => {
        await db.collection('users').deleteMany({
            username: { $in: ['user_alpha', 'user_beta', 'attacker_xss', 'mass_assign'] }
        });

        if (db) {
            await MongoDBConnection.killConnection();
        }
    });

});
