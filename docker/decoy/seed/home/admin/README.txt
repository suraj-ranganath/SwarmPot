# fileserver-01

Legacy file gateway kept online for the accounting migration. It fronts the
internal replica and holds nightly database snapshots under /home/admin/backup.

Do not store production credentials on this host. The replica credential in
secrets.env is read-only and expires at the end of the migration.

Contact: infra-ops@example.invalid
