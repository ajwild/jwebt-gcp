import { prepareSignOptions } from './sign';

const fakeCredentials = {
  type: 'service_account',
  project_id: 'jwebt',
  private_key_id: 'abcdefghijklmnopqrstuvwxyz01234567890123',
  private_key:
    '-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----\n',
  client_email: 'test@example.iam.gserviceaccount.com',
  client_id: '123456789012345678901',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url:
    'https://www.googleapis.com/robot/v1/metadata/x509/test%40example.iam.gserviceaccount.com',
};
const mockTime = new Date('2000-01-01T00:00:00.000Z').getTime();

describe('sign', () => {
  beforeEach(() => {
    jest.spyOn(global.Date, 'now').mockReturnValue(mockTime);
  });

  it('should successfully prepare a correctly formatted credentials file', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = 'https://logging.googleapis.com/';

    expect(prepareSignOptions({ credentials, audience })).toStrictEqual({
      payload: {
        aud: audience,
        iss: credentials.client_email,
        sub: credentials.client_email,
        exp: Math.floor(mockTime / 1000) + 60 * 60,
        iat: Math.floor(mockTime / 1000),
      },
      privateKey: credentials.private_key,
      keyId: credentials.private_key_id,
      format: 'pkcs8',
      algorithm: 'RS256',
      extractable: false,
      keyUsages: ['sign'],
      subtleCrypto: undefined,
    });
  });

  it('should throw an error when client_email is missing', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials, client_email: undefined as any };
    const audience = 'https://logging.googleapis.com/';

    expect(() => prepareSignOptions({ credentials, audience })).toThrow(
      new Error("'client_email' value is missing.")
    );
  });

  it('should throw an error when client_email is not a string', () => {
    expect.assertions(1);

    const credentials = {
      ...fakeCredentials,
      client_email: ['email@example.com'] as any,
    };
    const audience = 'https://logging.googleapis.com/';

    expect(() => prepareSignOptions({ credentials, audience })).toThrow(
      new TypeError("'client_email' type must be string, not object.")
    );
  });

  it('should throw an error when private_key is missing', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials, private_key: undefined as any };
    const audience = 'https://logging.googleapis.com/';

    expect(() => prepareSignOptions({ credentials, audience })).toThrow(
      new Error("'private_key' value is missing.")
    );
  });

  it('should throw an error when private_key is not a string', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials, private_key: 1 as any };
    const audience = 'https://logging.googleapis.com/';

    expect(() => prepareSignOptions({ credentials, audience })).toThrow(
      new TypeError("'private_key' type must be string, not number.")
    );
  });

  it('should throw an error when audience is missing', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = undefined as any;

    expect(() => prepareSignOptions({ credentials, audience })).toThrow(
      new Error("'audience' value is missing.")
    );
  });

  it('should throw an error when audience is not a string', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = ['https://logging.googleapis.com/'] as any;

    expect(() => prepareSignOptions({ credentials, audience })).toThrow(
      new TypeError("'audience' type must be string, not object.")
    );
  });

  it('should not throw an error when expiresInSeconds is missing', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = 'https://logging.googleapis.com/';

    expect(
      prepareSignOptions({
        credentials,
        audience,
        expiresInSeconds: undefined as any,
      })
    ).toHaveProperty('payload');
  });

  it('should throw an error when expiresInSeconds is not a number', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = 'https://logging.googleapis.com/';

    expect(() =>
      prepareSignOptions({
        credentials,
        audience,
        expiresInSeconds: 'test' as any,
      })
    ).toThrow(
      new TypeError("'expiresInSeconds' type must be number, not string.")
    );
  });

  it('should throw an error when expiresInSeconds is below 0', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = 'https://logging.googleapis.com/';

    expect(() =>
      prepareSignOptions({
        credentials,
        audience,
        expiresInSeconds: -1,
      })
    ).toThrow(
      new RangeError(
        "'expiresInSeconds' should be between 0 and 3600 (1 hour)."
      )
    );
  });

  it('should throw an error when expiresInSeconds is above 3600', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = 'https://logging.googleapis.com/';

    expect(() =>
      prepareSignOptions({
        credentials,
        audience,
        expiresInSeconds: 3601,
      })
    ).toThrow(
      new RangeError(
        "'expiresInSeconds' should be between 0 and 3600 (1 hour)."
      )
    );
  });

  it('should pass SubtleCrypto through', () => {
    expect.assertions(1);

    const credentials = { ...fakeCredentials };
    const audience = 'https://logging.googleapis.com/';
    const subtleCrypto = {};

    expect(
      prepareSignOptions({
        credentials,
        audience,
        subtleCrypto: subtleCrypto as SubtleCrypto,
      }).subtleCrypto
    ).toBe(subtleCrypto);
  });
});
