# @trustos/auth

Token validation and authorization guards.

## Claim shapes are provider-specific

`TokenValidator` classifies a token as `machine`, `human` or `unknown` from claims that
are **Keycloak's**, verified against 26.x:

| Marker              | Meaning                                    |
| ------------------- | ------------------------------------------ |
| `client_id` present | service-account token (client credentials) |
| `sid` present       | interactive session                        |
| neither             | `unknown`                                  |

Two things worth knowing before changing this:

1. **Keycloak 26 emits `sid`, not `session_state`.** Much documentation still says
   `session_state`; this version does not emit it. A check written against the older
   claim silently classifies every human token as a machine one.

2. **Both branches require positive evidence.** `unknown` exists so a gate that needs an
   interactively authenticated human fails closed rather than guessing. Inferring
   `human` from the absence of a machine marker is how a service account ends up
   satisfying an MFA requirement.

Swapping identity provider means revisiting this mapping. The rest of the validator —
issuer, audience, expiry, algorithm allowlist, JWKS key lookup — is standard OIDC.
