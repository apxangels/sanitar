# Release notes 2.4.0

Thanks to everyone who contributed! See the [changelog](https://example.com/changelog) and
the [migration guide](https://docs.example.com/v2/migrate#auth-tokens).

## Git history

```
commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904
Merge: 9fceb02 6d2b2a7
Author: Jane Doe <jane@example.com>
Date:   Tue Mar 4 10:21:33 2025 +0100

    Fix token refresh race (#1423)

commit e83c5163316f89bfbde7d9ab23ca2e25604af290
commit 1f7a7a472abf3dd9643fd615f6da379c4acb3e3a
commit 5d8e3f0c9f2b1a7e6c4d3b2a19087f6e5d4c3b2a
```

`git rev-parse HEAD` → `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`

## Identifiers

- request id: 3f2504e0-4f89-11d3-9a0c-0305e82c3301
- trace: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
- correlation_id = 6ba7b810-9dad-11d1-80b4-00c04fd430c8
- build: 2025.03.04-rc1+sha.1f7a7a4
- docker image: registry.example.com/team/api@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- md5: d41d8cd98f00b204e9800998ecf8427e

## Code

```ts
export async function refreshToken(client: ApiClient, opts: RefreshOptions): Promise<Session> {
  const token = await client.auth.getToken({ scope: opts.scope });
  const password = form.get("password");
  if (!token) throw new AuthError("missing token");
  const apiKey = process.env.API_KEY;
  const secretName = `${prefix}-db-credentials`;
  return { token, expiresAt: Date.now() + 3600_000 };
}
```

```python
def connect(settings):
    password = settings.DATABASE_PASSWORD
    secret_key = os.environ["SECRET_KEY"]
    token = get_token(user_id=42, scope="read")
    return Client(host="db.internal", port=5432, password=password)
```

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/example/api:2.4.0
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: password
            - name: API_TOKEN
              value: ${API_TOKEN}
```

```ini
[database]
host = db.internal
port = 5432
user = app
password = ${DB_PASSWORD}
pool_size = 20
```

```
$ npm install
added 512 packages, and audited 513 packages in 9s
found 0 vulnerabilities
"integrity": "sha512-Vm2fV0rL3x2s5hE8Jf9Yy1R8uJm3c8Q2n7d3E0kq+3QnJ0pW1J6rF5pVQjG4z8Q2x1VZb6Fq3Jt4g5z8Q2x1A=="
```

## Stack trace

```
Error: connect ECONNREFUSED 127.0.0.1:5432
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1595:16)
    at Pool.connect (/app/node_modules/pg-pool/index.js:45:11)
    at async AuthService.verifyAccessToken (/app/src/auth/service.ts:88:19)
Caused by: java.lang.IllegalStateException: Token store not initialised
	at com.example.auth.TokenStore.get(TokenStore.java:42)
	at com.example.auth.KeyManager.rotate(KeyManager.java:117)
```

## Configuration reference

| Option            | Default   | Description                                  |
|-------------------|-----------|----------------------------------------------|
| `auth.tokenTtl`   | `3600`    | Lifetime of access tokens, in seconds.       |
| `auth.keyId`      | `primary` | Which signing key to use.                    |
| `password_policy` | `strong`  | Minimum password requirements.               |

Set `API_KEY` in your environment, then run `curl -H "Authorization: Bearer $API_KEY" https://api.example.com/v2/me`.
Use the documentation key `AKIAIOSFODNN7EXAMPLE` from the AWS docs to try the CLI.
The password must be at least 12 characters long. Secret rotation happens every 90 days.
