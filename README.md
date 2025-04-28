# Shared Access Policy Token

## Overview

A shared access policy token (sometimes called a shared access signature or SAS token) is considered an easy way to secure an API or other online resources because:

- __Simple to generate:__ 
You just sign a URL or a request with a secret key and some rules (like expiry time, allowed permissions). No complicated authentication flows are needed.

- __No user management:__
You don't have to manage users, passwords, or OAuth flows — just distribute the signed token or signed URL. Perfect for service-to-service scenarios.

- __Scoped access:__
You can limit the token's permissions (read-only, write-only, etc.), resources (only a specific API or file), and valid time window (e.g., valid for only 1 hour). If it leaks, the damage is controlled.

- __Works anywhere:__
Tokens are just strings. You can send them easily in HTTP headers, URLs, or as query parameters, even with very basic clients.

- __Revocation is simple:__
If you sign tokens based on a policy or key, you can just rotate the key (invalidate it) and immediately revoke all issued tokens.

- __No backend calls required for auth:__
Once a client has the token, they can just use it — the server just verifies the signature and expiry locally, super fast.

