/**
 * Cryptographic utility for MAS-CSI
 * Real SHA-256 integrity verification via Web Crypto API
 */

export async function computeSha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function verifyEvidenceIntegrity(
  content: string,
  expectedHash: string
): Promise<{ isValid: boolean; calculatedHash: string }> {
  const calculated = await computeSha256(content);
  return {
    isValid: calculated.toLowerCase() === expectedHash.toLowerCase(),
    calculatedHash: calculated,
  };
}

export function generateSimpleId(prefix: string): string {
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `${prefix}-${Date.now().toString().slice(-6)}-${rand}`;
}
