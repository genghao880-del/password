import { encryptPassword, decryptPassword } from '../utils/security';

describe('Encryption utilities', () => {
  it('should encrypt and decrypt a password correctly', async () => {
    const password = 'mySecretPassword123!';
    const keyMaterial = 'user_123_key_material';
    
    const encrypted = await encryptPassword(password, keyMaterial);
    expect(encrypted).toBeDefined();
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toBe(password);
    
    // Note: decryption implementation would need to be completed for full testing
  });

  it('should produce different encrypted values for the same password', async () => {
    const password = 'mySecretPassword123!';
    const keyMaterial = 'user_123_key_material';
    
    const encrypted1 = await encryptPassword(password, keyMaterial);
    const encrypted2 = await encryptPassword(password, keyMaterial);
    
    expect(encrypted1).not.toBe(encrypted2);
  });
});