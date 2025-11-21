# Lophiid Database Setup Tool

This tool automates the setup and maintenance of the PostgreSQL database for Lophiid. It handles:
- Creating the database if it doesn't exist.
- Applying the schema (`config/database.sql`).
- Creating/updating the application user (`lo`) and granting permissions.
- Managing time-based partitions for the `request` table.

## Usage

```bash
./setup_db [flags]
```

### Flags

| Flag               | Default               | Description                                                 |
|--------------------|-----------------------|-------------------------------------------------------------|
| `--config`         | `backend-config.yaml` | Path to the backend configuration file.                     |
| `--db-host`        | `localhost`           | Database host address.                                      |
| `--db-user`        | `postgres`            | Database **superuser** username (required for admin tasks). |
| `--db-password`    | `postgres`            | Database **superuser** password.                            |
| `--db-name`        | `lophiid`             | Target database name to create/manage.                      |
| `--app-user`       | `lo`                  | Application username to create/update in the DB.            |
| `--app-password`   | `lo`                  | Application user password.                                  |
| `--schema-path`    | `./config/database.sql` | Path to the SQL schema file.                              |
| `--partitions-only`| `false`               | Only manage partitions (skip DB creation, schema, user setup). |

### Environment Variables

Environment variables can override defaults, but explicit flags take precedence.

- `DB_HOST`, `DB_PORT`, `DB_NAME`

## Examples

### 1. Initial Setup (Full Bootstrap)

Run this to set up a fresh environment. You need credentials for a database superuser (like `postgres`).

```bash
./setup_db \
  --db-host=localhost \
  --db-user=postgres \
  --db-password=secret_admin_pass \
  --app-password=secret_app_pass
```

This will:
1. Connect to `postgres` on `localhost`.
2. Create the database `lophiid` if missing.
3. Apply the schema from `./config/database.sql`.
4. Create the user `lo` with password `secret_app_pass` and grant permissions.
5. Create table partitions for the current and next year.

### 2. Partition Maintenance Only

Run this periodically (e.g., via cron) to ensure future time-based partitions exist. This mode requires less privileges if the user `lo` is already owner, but typically run as admin to be safe.

```bash
./setup_db --partitions-only --db-host=localhost --db-password=secret_admin_pass
```

### 3. Using a Custom Config File

If you have a backend config file, you can point to it. Note that the config file primarily supplies the Host/Port, but you still typically need to supply credentials via flags.

```bash
./setup_db --config=/etc/lophiid/backend-config.yaml --db-password=postgres
```
