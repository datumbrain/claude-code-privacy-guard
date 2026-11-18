/**
 * Opt-in PII detectors: credit card numbers, US SSNs, and phone numbers.
 *
 * These are deliberately NOT part of BUILTIN_RULES. They are enabled one by
 * one through the `piiProfile` config section and are off by default so the
 * tool stays coding-focused. Each rule pairs a loose candidate regex with a
 * strict validator (Luhn + issuer prefix, SSN range rules, NANP rules) so
 * order IDs, timestamps and version strings don't flood users with false
 * positives.
 */
/** Luhn checksum over a digit string. */
export function passesLuhn(digits) {
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let n = digits.charCodeAt(i) - 48;
        if (n < 0 || n > 9)
            return false;
        if (double) {
            n *= 2;
            if (n > 9)
                n -= 9;
        }
        sum += n;
        double = !double;
    }
    return digits.length > 0 && sum % 10 === 0;
}
// Issuer prefix + allowed lengths. A random Luhn-valid number (10% of all
// digit strings) must also start like a real card to be flagged.
const CARD_ISSUERS = [
    { prefix: /^4/, lengths: [13, 16, 19] }, // Visa
    { prefix: /^(?:5[1-5]|2(?:2[2-9]\d|[3-6]\d\d|7[01]\d|720))/, lengths: [16] }, // Mastercard
    { prefix: /^3[47]/, lengths: [15] }, // American Express
    { prefix: /^(?:6011|65|64[4-9])/, lengths: [16, 19] }, // Discover
    { prefix: /^(?:352[89]|35[3-8]\d)/, lengths: [16, 19] }, // JCB
    { prefix: /^3(?:0[0-5]|[68])/, lengths: [14] }, // Diners Club
];
export function isValidCardNumber(raw) {
    // Separators must be consistent: all spaces or all hyphens, never mixed.
    if (/ /.test(raw) && /-/.test(raw))
        return false;
    const digits = raw.replace(/[ -]/g, '');
    const issuer = CARD_ISSUERS.find((i) => i.prefix.test(digits));
    if (!issuer || !issuer.lengths.includes(digits.length))
        return false;
    return passesLuhn(digits);
}
export function isValidSsn(raw) {
    const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(raw);
    if (!m)
        return false;
    const area = Number(m[1]);
    const group = Number(m[2]);
    const serial = Number(m[3]);
    if (area === 0 || area === 666 || area >= 900)
        return false;
    if (group === 0 || serial === 0)
        return false;
    return true;
}
// North American Numbering Plan: area code and exchange start with 2-9, and
// area codes of the form N11 (211, 911, ...) are service codes.
function isValidNanp(tenDigits) {
    if (tenDigits.length !== 10)
        return false;
    const area = tenDigits.slice(0, 3);
    const exchange = tenDigits.slice(3, 6);
    const line = Number(tenDigits.slice(6));
    if (!/^[2-9]/.test(area) || !/^[2-9]/.test(exchange))
        return false;
    if (area.slice(1) === '11')
        return false;
    // 555-0100..0199 is reserved for fictional use (docs, examples, test data).
    if (exchange === '555' && line >= 100 && line <= 199)
        return false;
    return true;
}
export function isValidPhone(raw) {
    const digits = raw.replace(/\D/g, '');
    if (raw.startsWith('+')) {
        // E.164: up to 15 digits including the country code.
        if (digits.length < 8 || digits.length > 15)
            return false;
        if (digits.startsWith('1'))
            return isValidNanp(digits.slice(1));
        return true;
    }
    // US formats: optional leading country code 1, then 10 digits.
    const national = digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
    return isValidNanp(national);
}
export const PII_RULES = {
    creditCard: {
        id: 'pii-credit-card',
        title: 'Credit Card Number',
        description: 'Detects payment card numbers that pass a Luhn checksum and have a real issuer prefix and length',
        severity: 'high',
        category: 'financial',
        pattern: /(?<![\w.-])\d(?:[ -]?\d){12,18}(?![\w-])/g,
        examples: ['4111 1111 1111 1111'],
        redactionStrategy: 'token-replace',
        enabled: true,
        validate: (match) => isValidCardNumber(match),
    },
    ssn: {
        id: 'pii-ssn',
        title: 'US Social Security Number',
        description: 'Detects dashed SSNs (AAA-GG-SSSS), rejecting invalid area 000/666/9xx, group 00 and serial 0000',
        severity: 'high',
        category: 'pii',
        pattern: /(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])/g,
        examples: ['123-45-6789'],
        redactionStrategy: 'token-replace',
        enabled: true,
        validate: (match) => isValidSsn(match),
    },
    phone: {
        id: 'pii-phone',
        title: 'Phone Number',
        description: 'Detects E.164 and common US phone number formats, validated against NANP rules',
        severity: 'medium',
        category: 'pii',
        // US branch needs a separator between every group, so bare 10-digit
        // order IDs never match. E.164 branch needs a leading +.
        pattern: /(?<![\w.-])(?:(?:\+?1[ .-]?)?(?:\(\d{3}\)[ ]?|\d{3}[ .-])\d{3}[ .-]\d{4}|\+[1-9](?:[ .-]?\d){7,14})(?![\w-])/g,
        examples: ['(415) 555-2671'],
        redactionStrategy: 'token-replace',
        enabled: true,
        validate: (match) => isValidPhone(match),
    },
};
/** Rules enabled by a config's `piiProfile`; empty when nothing is opted in. */
export function getPiiRules(profile) {
    if (!profile)
        return [];
    return Object.keys(PII_RULES)
        .filter((key) => profile[key] === true)
        .map((key) => PII_RULES[key]);
}
