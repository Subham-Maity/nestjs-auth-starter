import { randomBytes } from 'crypto';

export interface OTPConfig {
  length: number;
  type: 'string' | 'number';
  lowerCaseAlphabets: boolean;
  upperCaseAlphabets: boolean;
  digits: boolean;
  specialChars: boolean;
}

export function generateOTP(config: OTPConfig): any {
  const lowerCase = 'abcdefghijklmnopqrstuvwxyz';
  const upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const special = '!@#$%^&*()_+~`|}{[]:;?><,./-=';

  let characters = '';
  if (config.lowerCaseAlphabets) characters += lowerCase;
  if (config.upperCaseAlphabets) characters += upperCase;
  if (config.digits) characters += numbers;
  if (config.specialChars) characters += special;

  let otp = '';
  for (let i = 0; i < config.length; i++) {
    const randomIndex = Math.floor(
      (randomBytes(1)[0] / 256) * characters.length,
    );
    otp += characters[randomIndex];
  }

  if (config.type === 'number') {
    return parseInt(otp, 10);
  }

  return otp;
}
