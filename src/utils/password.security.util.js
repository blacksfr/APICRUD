import { randomInt } from 'node:crypto';

const CHARSETS = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    nums: "0123456789",
    symb: "!@#$%^&*()_+-=[]{}|;:,.<>?"
};

/**
 * CSPRNG Password Generator (Enterprise Level)
 */
export function generateSecurePassword(length = 16) {
    // 1. Garante que o comprimento esteja entre 12 e 128
    const safeLength = Math.max(12, Math.min(length, 128));

    // 2. Garante Entropia Mínima: Um caractere de cada set obrigatoriamente
    // Definimos o array DENTRO da função para ser thread-safe
    let passwordArray = [
        CHARSETS.upper[randomInt(0, CHARSETS.upper.length)],
        CHARSETS.lower[randomInt(0, CHARSETS.lower.length)],
        CHARSETS.nums[randomInt(0, CHARSETS.nums.length)],
        CHARSETS.symb[randomInt(0, CHARSETS.symb.length)]
    ];

    // 3. Preenchimento Aleatório até atingir o safeLength
    const allChars = Object.values(CHARSETS).join('');
    while (passwordArray.length < safeLength) {
        passwordArray.push(allChars[randomInt(0, allChars.length)]);
    }

    // 4. Embaralhamento Fisher-Yates para evitar previsibilidade na ordem inicial
    for (let i = passwordArray.length - 1; i > 0; i--) {
        const j = randomInt(0, i + 1);
        [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
    }

    return passwordArray.join('');
}

/**
 * Calcula a Entropia da Senha (Bits)
 * Fórmula: E = L * log2(R)
 */
export function calculateEntropy(senha) {
    if (!senha) return 0;

    let poolSize = 0;
    if (/[a-z]/.test(senha)) poolSize += 26;
    if (/[A-Z]/.test(senha)) poolSize += 26;
    if (/[0-9]/.test(senha)) poolSize += 10;
    // Símbolos comuns (cerca de 32 caracteres)
    if (/[^a-zA-Z0-9]/.test(senha)) poolSize += 32;

    if (poolSize === 0) return 0;

    // Cálculo: Comprimento * log2(Tamanho do Pool)
    const entropy = senha.length * Math.log2(poolSize);
    return Math.floor(entropy);
}