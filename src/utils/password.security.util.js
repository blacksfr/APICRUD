import { randomInt } from 'node:crypto';

const CHARSETS = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    nums: "0123456789",
    symb: "!@#$%^&*()_+-=[]{}|;:,.<>?"
};

export function generateSecurePassword(length = 16) {
    const safeLength = Math.max(12, Math.min(length, 128));

    let passwordArray = [
        CHARSETS.upper[randomInt(0, CHARSETS.upper.length)],
        CHARSETS.lower[randomInt(0, CHARSETS.lower.length)],
        CHARSETS.nums[randomInt(0, CHARSETS.nums.length)],
        CHARSETS.symb[randomInt(0, CHARSETS.symb.length)]
    ];

    const allChars = Object.values(CHARSETS).join('');
    while (passwordArray.length < safeLength) {
        passwordArray.push(allChars[randomInt(0, allChars.length)]);
    }

    for (let i = passwordArray.length - 1; i > 0; i--) {
        const j = randomInt(0, i + 1);
        [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
    }

    return passwordArray.join('');
}

export function calculateEntropy(senha) {
    if (!senha) return 0;

    let poolSize = 0;
    if (/[a-z]/.test(senha)) poolSize += 26;
    if (/[A-Z]/.test(senha)) poolSize += 26;
    if (/[0-9]/.test(senha)) poolSize += 10;
    
    if (/[^a-zA-Z0-9]/.test(senha)) poolSize += 32;

    if (poolSize === 0) return 0;

    const entropy = senha.length * Math.log2(poolSize);
    return Math.floor(entropy);
}