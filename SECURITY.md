# Security

## Reporting a vulnerability

Report vulnerabilities to strata-sec@xmx.starkweb.io.

## Supported versions

The project is pre-1.0. Security fixes go into `main` and into the next release
image. Earlier images get no fixes.

A candidate image and a stable image from `main` have a cosign signature with the
same certificate identity,
`https://github.com/AlectoTheFirst/HST/.github/workflows/release.yml@refs/heads/main`.
The identity proves that `release.yml` on `main` built the digest. A stable image
has a second signature with the annotation `channel=stable`. The job `promote`
writes it after the `ci` workflow passed. Verify a stable image with
`-a channel=stable`. [deploy/helm/hst/README.md](deploy/helm/hst/README.md) has
the verify command.

A tag on ghcr.io is not proof of a release. A person with write access to the
repository can push any tag from a branch. Only the signature check proves the
origin of a digest.

## Scope

Authentication uses local accounts with argon2id password hashes and a session
cookie, or OIDC and SAML providers that an admin configures. Personal access
tokens authenticate clients on `/api/mcp` and `/api/graphql`, and only the hash
of a token is stored. Authorization is an application-level permission check
over the roles viewer, operator and admin. The graph has no per-user privileges. The compose
stack binds the Neo4j bolt port to loopback.

These faults are in scope:

- Source credentials, AI provider keys or raw device snapshots that are readable
  through the API, logs or error messages.
- Authentication and role-gate bypasses.
- Escapes from the read-only Cypher surface (`/api/cypher`) into writes or
  server-side file access.
- Reads through the GraphQL endpoint (`/api/graphql`) outside the run a request
  pins, past its depth, alias, token, page and cost limits, or without the
  permission a field declares.
- SSH host-key pinning bypasses in the collectors.
- Use of a personal access token on `/api/mcp` outside its scope (`read` or
  `read-write`), or on `/api/mcp` or `/api/graphql` outside the permissions of
  its user.
- Faults in the SAML and OIDC sign-in flows: a response or a token that is
  accepted without a valid signature, a login as a different user, or a bypass of
  the break-glass guards.
- Text from a collected device or a stored record that makes the model of HST AI
  call a tool outside the permissions of the user.
- An HST AI answer that reads a run other than the run of its question and does
  not list that run. A tool call reads the run of the question unless the call
  names another retained run. The answer lists each other run and marks each
  statement that cites it as `cross-snapshot`.
- Secret material that reaches the model provider of HST AI.
- A package key that opens data outside its assessment package.

## Hardening expectations

The stack serves plain HTTP by default. An untrusted network needs a TLS
terminator in front of the stack. Without a terminator, `hst serve` terminates
TLS itself when `TLS_CERT_FILE` and `TLS_KEY_FILE` are set. A cookie over plain
HTTP without a terminator is not a finding.

The login limit counts attempts for each client address. Behind a terminator, set
`HST_FORWARDED_ALLOW_IPS` to the address of the terminator. With the setting
empty, all clients behind the terminator count as 1 address.
