# Compose secrets

`docker-compose.ha.yml` mounts these files as Docker secrets. Create them before
bringing up the stack; **do not commit real secrets** (this folder's `.gitignore`
ignores everything except itself and this README).

> The directory is named `compose-secrets` rather than `secrets` on purpose: the
> repository root `.gitignore` ignores any `secrets/` directory wholesale, which
> would also hide this README. The contents here are still ignored.

```sh
# 32+ chars of real entropy — losing it means losing all managed keys.
printf '%s' 'replace-with-a-strong-operator-passphrase' > pqkms_passphrase
printf '%s' 'replace-with-a-strong-postgres-password'   > postgres_password
printf '%s' 'replace-with-a-strong-grafana-password'    > grafana_password
chmod 600 pqkms_passphrase postgres_password grafana_password
```

The app reads the operator passphrase from the mounted file via
`PQKMS_PASSPHRASE_FILE=/run/secrets/pqkms_passphrase`, so it never appears in an
environment variable or `docker inspect`.
