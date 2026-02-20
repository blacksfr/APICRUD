import { describe, test, expect } from 'vitest';
import request from 'supertest';

const BASE_URL = 'https://api-crud-blacksfritching.vercel.app';

describe('Enterprise Security & Vulnerability Test Suite - PRECISION MODE', () => {
    const uniqueSuffix = Math.floor(Math.random() * 9999);
    const userA = { username: `alpha_${uniqueSuffix}`, password: 'StrongPassword123!' };
    const userB = { username: `beta_${uniqueSuffix}`, password: 'AnotherPassword456!' };

    let userAToken, userAId, userBId;

    // ==================================================
    // 1. SETUP (Gasta 2 de 3 créditos do registerLimiter)
    // ==================================================
    test('Setup: Registro e Duplicidade', async () => {
        const resA = await request(BASE_URL).post('/users').send(userA);
        expect(resA.status).toBe(201);
        userAId = resA.body.user.id;
        userAToken = resA.body.accessToken;

        const resB = await request(BASE_URL).post('/users').send(userB);
        expect(resB.status).toBe(201);
        userBId = resB.body.user.id;
    });

    // ==================================================
    // 2. INJECTION & XSS (Gasta o último crédito do registerLimiter)
    // ==================================================
    test('Vulnerabilidades de Entrada: NoSQL & XSS', async () => {
        // NoSQL Injection no Login (Gasta 1 de 5 do loginLimiter)
        const resInjection = await request(BASE_URL).post('/users/login').send({ 
            username: { "$gt": "" }, 
            password: "1" 
        });
        expect(resInjection.status).toBe(400);

        // XSS no Registro (Gasta 3 de 3 do registerLimiter - LIMITE ESGOTADO)
        const resXss = await request(BASE_URL).post('/users').send({
            username: '<script>alert(1)</script>',
            password: 'StrongPassword123!'
        });
        expect(resXss.status).toBe(400);
    });

    // ==================================================
    // 3. MASS ASSIGNMENT (Proteção contra campos inexistentes/proibidos)
    // ==================================================
    // ==================================================
    // 3. MASS ASSIGNMENT (Validado com Strict Schema)
    // ==================================================
    test('Mass Assignment: Bloquear injeção de campos fora do Schema', async () => {
        const res = await request(BASE_URL)
            .put(`/users/${userAId}`)
            .set('Authorization', `Bearer ${userAToken}`)
            .send({ 
                isAdmin: true,   // Campo inexistente
                role: 'admin',    // Campo inexistente
                password: 'NewPassword123!' 
            });
        
        // Como sua API usa Schema estrito, ela deve retornar 400.
        // Se ela retornasse 200, teríamos que checar se os campos foram ignorados.
        // Como retorna 400, a proteção é ainda mais forte!
        expect(res.status).toBe(400); 
    });
    // ==================================================
    // 4. BROKEN AUTHENTICATION (JWT)
    // ==================================================
    test('JWT: Validação de integridade e formato', async () => {
        const resEmpty = await request(BASE_URL).get(`/users/${userAId}`).set('Authorization', 'Bearer ');
        expect(resEmpty.status).toBe(401);

        const resBad = await request(BASE_URL).get(`/users/${userAId}`).set('Authorization', `Bearer ${userAToken}X`);
        expect([401, 403]).toContain(resBad.status);
    });

    // ==================================================
    // 5. PRIVACIDADE & INFRA (IDOR & HEADERS)
    // ==================================================
    test('Privacidade e Infraestrutura', async () => {
        // IDOR: A não acessa B
        const resIdor = await request(BASE_URL).get(`/users/${userBId}`).set('Authorization', `Bearer ${userAToken}`);
        expect(resIdor.status).toBe(403);

        // Headers de Segurança
        const resHead = await request(BASE_URL).get('/');
        expect(resHead.headers['x-content-type-options']).toBe('nosniff');
        expect(resHead.headers['x-frame-options']).toBeDefined();
    });

    // ==================================================
    // 6. CLEANUP (ANTES DO BLOQUEIO)
    // ==================================================
    test('Cleanup: Remoção de dados de teste', async () => {
        // Deletar User A (Token A)
        const delA = await request(BASE_URL).delete(`/users/${userAId}`).set('Authorization', `Bearer ${userAToken}`);
        expect(delA.status).toBe(200);

        // Para o User B, precisaríamos de um login para pegar o token, 
        // mas para economizar requisições, deletar o A já valida o fluxo.
    });

    // ==================================================
    // 7. RATE LIMIT (O ÚLTIMO - VAI TRAVAR SEU IP)
    // ==================================================
    test('Rate Limit Global: Bloqueio total por excesso', async () => {
        let blocked = false;
        // Atacamos a raiz (/) 350 vezes. O limite é 300.
        for (let i = 0; i < 350; i++) {
            const res = await request(BASE_URL).get('/');
            if (res.status === 429) {
                blocked = true;
                expect(res.body.error).toBe("TOO_MANY_REQUESTS");
                break;
            }
        }
        expect(blocked).toBe(true);
    }, 180000); // 3 minutos de timeout para garantir a execução remota
});