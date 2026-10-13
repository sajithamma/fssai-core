# fssai-core

Look up an FSSAI licence or registration number on FoSCoS (foscos.fssai.gov.in), the same
data the public "FBO Search" page shows. No dependencies, Node 20+.

## CLI

```bash
node bin/fssai.js 12421012003663
node bin/fssai.js 12421012003663 --products   # also list licensed food products
node bin/fssai.js 12421012003663 --json       # full result incl. raw FoSCoS record
```

Exit codes: `0` found, `1` no record, `2` bad input, `3` network/server error.

## Library

```js
import { lookupFssai, FoscosClient } from 'fssai-core';

const info = await lookupFssai('12421012003663', { products: true });
// { fssaiNumber, companyName, address, district, state, licenseCategory, status,
//   kindOfBusiness, issuedOn, validUpto, refId, raw, products? }  or null

const client = new FoscosClient({ timeoutMs: 20000 }); // reuse for many lookups
```

## How it works

1. `GET /gateway/api/auth/csrf-token` to get the session cookie.
2. `POST /webgateway/commonauth_readonly/commonapi/getsearchapplicationdetails/1` with
   `{"encryptedPayload": AES-128-ECB(JSON query)}`.
3. The response is `{encryptedResponse, signature}`: the RSA-SHA256 signature is checked against
   FoSCoS's public key (`src/foscos-response-public.pem`), then the body is AES-decrypted.

The keys come from the public FoSCoS frontend bundle. If FSSAI changes them, update `src/crypto.js`.
The site captcha is only checked in the browser, so it is not needed here.

## Geo-blocking

FoSCoS normally only answers Indian IP addresses. From outside India, use an Indian proxy:

```bash
NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://user:pass@in-proxy:port node bin/fssai.js 12421012003663
```

## Tests

```bash
npm test
```

## For testers in India

```bash
git clone https://github.com/sajithamma/fssai-core.git
cd fssai-core
node bin/fssai.js <14-digit FSSAI number>
node bin/fssai.js <14-digit FSSAI number> --json --products
```

Please report back the `--json` output for a couple of real numbers (from any food packet), or the exact error.
Field names in the summary were inferred from the FoSCoS frontend, so the raw record helps confirm them.
