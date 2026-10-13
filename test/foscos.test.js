import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { FoscosClient, FoscosError, normaliseFssaiNumber, summariseRecord } from '../src/foscos.js';
import { PAYLOAD_KEY, RESPONSE_KEY, decryptResponse, encryptPayload } from '../src/crypto.js';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const TEST_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' });

function signedEncrypted(obj, key = privateKey) {
  const encryptedResponse = encryptPayload(JSON.stringify(obj), RESPONSE_KEY);
  const signature = crypto.sign('sha256', Buffer.from(encryptedResponse), key).toString('base64');
  return { encryptedResponse, signature };
}

const RECORD = {
  refId: 987654,
  licenseno: '12421012003663',
  companyname: 'ACME FOODS PRIVATE LIMITED',
  premiseaddress: '12 MG Road, Kochi',
  districtname: 'Ernakulam',
  statename: 'Kerala',
  licensecategoryid: 2,
  licensecategoryname: 'State License',
  statusdesc: 'Active',
  kobname: 'Manufacturer',
};

// Minimal fake FoSCoS: records every call and answers by path.
function fakeFoscos(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const path = new URL(url).pathname;
    calls.push({ path, init });
    const handler = routes[path];
    if (!handler) return new Response('not found', { status: 404 });
    const { status = 200, body, headers = {} } = handler(init);
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
  };
  return { fetch, calls };
}

const CSRF = '/gateway/api/auth/csrf-token';
const SEARCH = '/webgateway/commonauth_readonly/commonapi/getsearchapplicationdetails/1';

function standardRoutes(records = [RECORD]) {
  return {
    [CSRF]: () => ({
      body: signedEncrypted({ message: 'Token generated successfully', status: 'success' }),
      headers: { 'Set-Cookie': 'csrf_token=abc123; Path=/; HttpOnly' },
    }),
    [SEARCH]: () => ({
      body: signedEncrypted({ paginationListRecords: records, pageLimit: 10, currentPageNo: 1 }),
    }),
  };
}

test('normaliseFssaiNumber accepts 14 digits with spaces or dashes', () => {
  assert.equal(normaliseFssaiNumber('124 2101 2003 663'), '12421012003663');
  assert.equal(normaliseFssaiNumber('12421-012003663'), '12421012003663');
  assert.equal(normaliseFssaiNumber(12421012003663), '12421012003663');
});

test('normaliseFssaiNumber rejects anything that is not 14 digits', () => {
  for (const bad of ['', '1234', '1242101200366X', '124210120036631', null, undefined]) {
    assert.throws(() => normaliseFssaiNumber(bad), (err) => err instanceof FoscosError && err.code === 'INVALID_NUMBER');
  }
});

test('summariseRecord maps FoSCoS fields case-insensitively', () => {
  const s = summariseRecord({ ...RECORD, CompanyName: undefined, StateName: 'ignored-if-statename-set' });
  assert.equal(s.fssaiNumber, '12421012003663');
  assert.equal(s.companyName, 'ACME FOODS PRIVATE LIMITED');
  assert.equal(s.state, 'Kerala');
  assert.equal(s.licenseCategory, 'State License');
  assert.equal(s.status, 'Active');
  assert.equal(s.validUpto, null);
});

test('lookup gets a CSRF session, sends an encrypted search and decodes the result', async () => {
  const { fetch, calls } = fakeFoscos(standardRoutes());
  const client = new FoscosClient({ fetch, publicKey: TEST_PUBLIC_KEY });

  const result = await client.lookup('12421012003663');

  assert.equal(calls.length, 2);
  assert.equal(calls[0].path, CSRF);
  assert.equal(calls[1].path, SEARCH);

  const search = calls[1].init;
  assert.equal(search.method, 'POST');
  assert.equal(search.headers.Cookie, 'csrf_token=abc123');
  assert.equal(search.headers['X-CSRF-TOKEN'], 'abc123');
  assert.equal(search.headers['Content-Type'], 'application/json');

  const { encryptedPayload } = JSON.parse(search.body);
  assert.deepEqual(JSON.parse(decryptResponse(encryptedPayload, PAYLOAD_KEY)), {
    premiseState: null,
    premiseDistrict: null,
    companyName: null,
    flrsLicenseNo: '12421012003663',
  });

  assert.equal(result.companyName, 'ACME FOODS PRIVATE LIMITED');
  assert.equal(result.status, 'Active');
  assert.deepEqual(result.raw, RECORD);
  assert.equal(result.products, undefined);
});

test('the CSRF session is fetched once per client', async () => {
  const { fetch, calls } = fakeFoscos(standardRoutes());
  const client = new FoscosClient({ fetch, publicKey: TEST_PUBLIC_KEY });
  await client.lookup('12421012003663');
  await client.lookup('12421012003663');
  assert.deepEqual(
    calls.map((c) => c.path),
    [CSRF, SEARCH, SEARCH],
  );
});

test('lookup returns null when FoSCoS has no record', async () => {
  const { fetch } = fakeFoscos(standardRoutes([]));
  const client = new FoscosClient({ fetch, publicKey: TEST_PUBLIC_KEY });
  assert.equal(await client.lookup('10000000000000'), null);
});

test('lookup prefers the record whose licence number matches exactly', async () => {
  const other = { ...RECORD, licenseno: '11111111111111', companyname: 'OTHER' };
  const { fetch } = fakeFoscos(standardRoutes([other, RECORD]));
  const client = new FoscosClient({ fetch, publicKey: TEST_PUBLIC_KEY });
  assert.equal((await client.lookup('12421012003663')).companyName, 'ACME FOODS PRIVATE LIMITED');
});

test('plain (unencrypted) JSON responses are accepted too', async () => {
  const { fetch } = fakeFoscos({
    [CSRF]: () => ({ body: { status: 'success' } }),
    [SEARCH]: () => ({ body: { paginationListRecords: [RECORD] } }),
  });
  const client = new FoscosClient({ fetch, publicKey: TEST_PUBLIC_KEY });
  assert.equal((await client.lookup('12421012003663')).district, 'Ernakulam');
});

test('a response signed with the wrong key is rejected', async () => {
  const { privateKey: wrongKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const routes = standardRoutes();
  routes[SEARCH] = () => ({ body: signedEncrypted({ paginationListRecords: [RECORD] }, wrongKey) });
  const client = new FoscosClient({ fetch: fakeFoscos(routes).fetch, publicKey: TEST_PUBLIC_KEY });
  await assert.rejects(client.lookup('12421012003663'), { code: 'BAD_SIGNATURE' });
});

test('HTTP errors surface as FoscosError', async () => {
  const routes = standardRoutes();
  routes[SEARCH] = () => ({ status: 429, body: 'Too many requests' });
  const client = new FoscosClient({ fetch: fakeFoscos(routes).fetch, publicKey: TEST_PUBLIC_KEY });
  await assert.rejects(client.lookup('12421012003663'), { code: 'HTTP_ERROR', message: /HTTP 429/ });
});

test('timeouts produce a hint about FoSCoS geo-blocking', async () => {
  const fetch = async () => {
    throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });
  };
  const client = new FoscosClient({ fetch });
  await assert.rejects(client.lookup('12421012003663'), { code: 'TIMEOUT', message: /Indian IP/ });
});

test('products come from the licence endpoint for licences and the registration endpoint for registrations', async () => {
  const routes = {
    ...standardRoutes([RECORD]),
    '/gateway/common/signup/getfboapplicationkobproducts/987654': () => ({
      body: signedEncrypted([{ productName: 'Biscuits' }]),
    }),
  };
  const client = new FoscosClient({ fetch: fakeFoscos(routes).fetch, publicKey: TEST_PUBLIC_KEY });
  assert.deepEqual((await client.lookup('12421012003663', { products: true })).products, [{ productName: 'Biscuits' }]);

  const registration = { ...RECORD, licensecategoryid: 3 };
  const regFake = fakeFoscos({
    ...standardRoutes([registration]),
    '/gateway/common/signup/getfboregistrationkobproducts/987654': () => ({ body: [{ productName: 'Tea' }] }),
  });
  const regClient = new FoscosClient({ fetch: regFake.fetch, publicKey: TEST_PUBLIC_KEY });
  assert.deepEqual((await regClient.lookup('12421012003663', { products: true })).products, [{ productName: 'Tea' }]);
});

test('a failing product lookup does not fail the whole lookup', async () => {
  const client = new FoscosClient({ fetch: fakeFoscos(standardRoutes()).fetch, publicKey: TEST_PUBLIC_KEY });
  const result = await client.lookup('12421012003663', { products: true });
  assert.equal(result.companyName, 'ACME FOODS PRIVATE LIMITED');
  assert.deepEqual(result.products, []);
  assert.match(result.productsError, /HTTP 404/);
});
