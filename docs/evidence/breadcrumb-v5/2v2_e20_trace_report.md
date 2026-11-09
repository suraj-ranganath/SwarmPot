# Episode trace report

- episode: `runs/20261109T054814Z-cve-2024-2624-e-r20-2d5cef`
- attacker agents: swarmpot-attack-1, swarmpot-attack-2, swarmpot-attack-3
- defender agents: defender-1, defender-2
- decisions: 32
- committed edits: 7
- board messages/reads: 1/6
- 2v2 present: attackers=True defenders=True
- edit followed by attacker reference: False

## Edit chains

### `edit-defender-1-0001` /home/admin/backup/migration_manifest.txt

- committed: 2026-11-09T05:56:24.257+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000125` request `defender-request-d0de66eaf84b472e815b718fadb9f236`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000033` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


### `edit-defender-1-0002` /home/admin/.ssh/known_hosts

- committed: 2026-11-09T05:56:24.258+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000125` request `defender-request-d0de66eaf84b472e815b718fadb9f236`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000033` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


### `edit-defender-2-0001` /home/admin/backup/backup.log

- committed: 2026-11-09T05:56:27.340+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000131` request `defender-request-8fae420196ba44829c5f7a90c25a3b89`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000026` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


### `edit-defender-2-0002` /home/admin/upload/README.txt

- committed: 2026-11-09T05:56:27.341+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000131` request `defender-request-8fae420196ba44829c5f7a90c25a3b89`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000026` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


### `edit-defender-2-0003` /home/admin/uploads/2026-11-08/accounts_export.csv

- committed: 2026-11-09T05:57:23.534+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000169` request `defender-request-82576dd71e9a4c2a81633111ef55f178`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000026` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


### `edit-defender-2-0004` /home/admin/uploads/MANIFEST.txt

- committed: 2026-11-09T05:57:23.534+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000169` request `defender-request-82576dd71e9a4c2a81633111ef55f178`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000026` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


### `edit-defender-1-0003` /home/admin/backup/backup.log

- committed: 2026-11-09T05:57:52.870+00:00
- decision: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000186` request `defender-request-445ca85e1eb34e6b8e735f7e8d81bffd`
- observation event: `evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000033` (3 SSH records)
- subsequent attacker references: 0
- exposure: no_subsequent_reference (version known: False)


## Board chains

### message 1 by defender-1

- delivered to: ['defender-2']
- read by: ['defender-1', 'defender-2']
- in decision context: ['evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000211', 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000289', 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000298', 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000306', 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000310']
- board body: defender-1: intruder (172.31.251.4) logged in as admin, ran recon batches: (1) id/hostname/ls /, (2) cat README/.ops-notes/secrets.env/.bash_history + ls -laR backup deploy, (3) /etc/hosts, resolv.conf, ps aux, ss/netstat, cron. Added /home/admin/backup/migration_manifest.txt, /home/admin/.ssh/known_hosts, /home/admin/backup/backup.log to keep the backup story consistent. No overlap needed unless you're editing backup/ or .ssh/.
- subsequent tool calls: [{'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000212', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/backup/backup.log'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000213', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000290', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/.bash_history'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000291', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/.ops-notes'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000292', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/backup/backup.log'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000293', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/backup/users.sql'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000294', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/upload/README.txt'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000295', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/uploads/MANIFEST.txt'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000299', 'tool': 'read_session', 'status': 'observed', 'edit_id': None, 'path': None}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000300', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000307', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/uploads/2026-11-08'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000308', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000311', 'tool': 'read_session', 'status': 'observed', 'edit_id': None, 'path': None}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000312', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/.bash_history'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000313', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/.ops-notes'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000314', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/secrets.env'}, {'event_id': 'evt-20261109T054814Z-cve-2024-2624-e-r20-2d5cef-000315', 'tool': 'read_decoy_files', 'status': 'observed', 'edit_id': None, 'path': '/home/admin/README.txt'}]
