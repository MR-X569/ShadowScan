/**
 * Frontend validation helpers aligned with backend policies.
 */

const LOCAL_PART_REGEX = /^[a-zA-Z0-9_+-]+(?:\.[a-zA-Z0-9_+-]+)*$/;
const DOMAIN_LABEL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const TLD_REGEX = /^[a-zA-Z]{2,63}$/;

export function isValidEmail(emailStr: string): boolean {
  if (!emailStr || typeof emailStr !== 'string') return false;
  const email = emailStr.trim().toLowerCase();

  if (email.length > 254) return false;
  if ((email.match(/@/g) || []).length !== 1) return false;

  const [localPart, domainPart] = email.split('@');
  if (!localPart || localPart.length > 64) return false;
  if (localPart.includes('..')) return false;
  if (!LOCAL_PART_REGEX.test(localPart)) return false;

  // Policy rule: local-part must contain at least one letter (rejects pure digits like 123@gmail.com)
  if (!/[a-zA-Z]/.test(localPart)) return false;

  if (!domainPart || domainPart.includes('..')) return false;

  const labels = domainPart.split('.');
  if (labels.length < 2) return false;

  for (const label of labels) {
    if (!label || !DOMAIN_LABEL_REGEX.test(label)) return false;
  }

  const tld = labels[labels.length - 1];
  if (!TLD_REGEX.test(tld)) return false;

  return true;
}

export function isValidUsername(username: string): boolean {
  if (!username || typeof username !== 'string') return false;
  const clean = username.trim();
  return clean.length >= 3 && clean.length <= 50;
}

export function isValidLoginIdentifier(identifier: string): boolean {
  if (!identifier || typeof identifier !== 'string') return false;
  const clean = identifier.trim();
  if (clean.includes('@')) {
    return isValidEmail(clean);
  }
  return isValidUsername(clean);
}
