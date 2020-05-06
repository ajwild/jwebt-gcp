import { SignOptions } from 'jwebt';

export type PrepareSignOptions = {
  readonly credentials: {
    readonly [key: string]: any;
    readonly client_email: string;
    readonly private_key: string;
    readonly private_key_id?: string;
  };
  readonly audience: string;
  readonly expiresInSeconds?: number;
};
export { SignOptions } from 'jwebt';

function validateInput({
  client_email,
  private_key,
  audience,
  expiresInSeconds,
}: {
  readonly client_email: string;
  readonly private_key: string;
  readonly audience: string;
  readonly expiresInSeconds: number;
}): boolean {
  type ValidationTuple = readonly [any, string];
  Object.entries({
    client_email: [client_email, 'string'],
    private_key: [private_key, 'string'],
    audience: [audience, 'string'],
    expiresInSeconds: [expiresInSeconds, 'number'],
  } as { readonly [key: string]: ValidationTuple }).forEach(
    ([key, [value, type]]: readonly [string, ValidationTuple]) => {
      if (!value) {
        throw new Error(`'${key}' value is missing.`);
      }

      if (typeof value !== type) {
        throw new TypeError(
          `'${key}' type must be ${type}, not ${typeof value}.`
        );
      }
    }
  );

  if (expiresInSeconds > 3600 || expiresInSeconds < 0) {
    throw new RangeError(
      "'expiresInSeconds' should be between 0 and 3600 (1 hour)."
    );
  }

  return true;
}

export function prepareSignOptions({
  credentials: { client_email, private_key, private_key_id },
  audience,
  expiresInSeconds = 60 * 60,
}: PrepareSignOptions): SignOptions {
  validateInput({
    client_email,
    private_key,
    audience,
    expiresInSeconds,
  });

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + expiresInSeconds;
  const payload = {
    aud: audience,
    iss: client_email,
    sub: client_email,
    exp,
    iat,
  };

  return {
    payload,
    privateKey: private_key,
    keyId: private_key_id,
    format: 'pkcs8',
    algorithm: 'RS256',
    extractable: false,
    keyUsages: ['sign'],
  };
}
