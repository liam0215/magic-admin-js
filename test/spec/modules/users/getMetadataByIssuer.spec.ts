import { createMagicAdminSDK } from '../../../lib/factories';
import { API_KEY } from '../../../lib/constants';
import { createApiKeyMissingError } from '../../../../src/core/sdk-exceptions';
import { get } from '../../../../src/utils/rest';

const successRes = Promise.resolve({
  issuer: 'foo',
  public_address: 'bar',
  email: 'baz',
  oauth_provider: 'foo1',
  phone_number: '+1234',
});
const nullRes = Promise.resolve({});

test('#01: Successfully GETs to metadata endpoint via issuer', async () => {
  const sdk = createMagicAdminSDK('https://example.com');

  const getStub = jest.fn().mockImplementation(() => successRes);
  (get as any) = getStub;

  const result = await sdk.users.getMetadataByIssuer('did:ethr:0x1234');

  const getArguments = getStub.mock.calls[0];
  expect(getArguments).toEqual(['https://example.com/v1/admin/auth/user/get', API_KEY, { issuer: 'did:ethr:0x1234' }]);
  expect(result).toEqual({
    issuer: 'foo',
    publicAddress: 'bar',
    email: 'baz',
    oauthProvider: 'foo1',
    phoneNumber: '+1234',
  });
});

test('#02: Successfully GETs `null` metadata endpoint via issuer', async () => {
  const sdk = createMagicAdminSDK('https://example.com');

  const getStub = jest.fn().mockImplementation(() => nullRes);
  (get as any) = getStub;

  const result = await sdk.users.getMetadataByIssuer('did:ethr:0x1234');

  const getArguments = getStub.mock.calls[0];
  expect(getArguments).toEqual(['https://example.com/v1/admin/auth/user/get', API_KEY, { issuer: 'did:ethr:0x1234' }]);
  expect(result).toEqual({
    issuer: null,
    publicAddress: null,
    email: null,
    oauthProvider: null,
    phoneNumber: null,
  });
});

test('#03: Fails GET if API key is missing', async () => {
  const sdk = createMagicAdminSDK('https://example.com');
  (sdk as any).secretApiKey = undefined;

  const getStub = jest.fn().mockImplementation();
  (get as any) = getStub;

  const expectedError = createApiKeyMissingError();
  expect(sdk.users.getMetadataByIssuer('did:ethr:0x1234')).rejects.toThrow(expectedError);

  expect(getStub).not.toBeCalled();
});
