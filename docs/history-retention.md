# History and how long it is kept

PegaProx keeps two kinds of history in its database: the metrics snapshots behind Reports,
Insights, Costs, Power and the node and guest charts, and the drift events of Config Drift
Detection. Both are kept per instance (a PegaProx HA standby keeps its own and never syncs
them). The settings below are environment variables of the PegaProx service: in the systemd
unit (`Environment=` lines, then `systemctl daemon-reload` and a restart) or in the
`environment:` section of the Docker container.

## Metrics history

Every five minutes PegaProx stores a snapshot of each connected cluster: the nodes, the
guests, the storage and the totals.

| Variable | Default | Meaning |
|---|---|---|
| `PEGAPROX_METRICS_RETENTION_DAYS` | `30` | Days of snapshots kept, 7 to 365. Older ones are deleted with every new snapshot. |
| `PEGAPROX_HEAVY_READ_TTL` | `60` | Seconds a large history read (the report windows) is kept in memory for the next request. |
| `PEGAPROX_HEAVY_READ_MAX_KEYS` | `64` | How many of those reads are kept at most, at least 1 (a value that is no whole number means 64). Past it, the ones that expire first make room; expired ones are dropped on every read and after every snapshot. |

### Stored per cluster, in parts

A snapshot used to be one JSON document of the whole fleet, about 0.3 MB at 3,000 guests and
1.1 MB at 10,000, and every page that read the history read all of it. It is now stored per
cluster and in parts (nodes, guests, storage, totals), the guests in a compact column format
that repeats what does not change between snapshots only once. At 3,000 guests the history
takes about a tenth of the space it took, and Reports, Costs, Power, right-sizing and the
charts read only the part they show.

Snapshots written by an older version are converted in the background, starting a minute
after PegaProx starts, newest first, one snapshot at a time and at most about a third of one
CPU core. Until a snapshot is converted it is read as before, so every page shows the full
history from the first start. When the conversion has finished, the log says so in one line
(`[metrics] stored snapshots converted to parts: ...`).

**Going back to an older version.** An older version cannot read the converted snapshots and
shows only the history it writes itself from then on. Nothing is lost: after the next update
the converted history is there again, and the snapshots the older version wrote meanwhile are
converted as well.

### The database file keeps its size

The conversion frees the space the old JSON documents took inside the database, and new
snapshots reuse it, so the file stops growing. It does not shrink, though: PegaProx never
compacts the database on its own, because that rewrites the whole file and needs as much free
disk again while it runs.

To give the space back to the file system, compact it by hand once the conversion has
finished, with PegaProx stopped and a copy of the `config` directory taken. Run this as the
user the service runs as, in the directory it runs in (`WorkingDirectory=` of the unit, for
an installation by `deploy.sh` `/opt/PegaProx`), with the Python PegaProx runs on:

```bash
sudo systemctl stop pegaprox
cd /opt/PegaProx
sudo -u pegaprox venv/bin/python -c "from pegaprox import constants; from pegaprox.core import dbcrypto; c = dbcrypto.connect(constants.DATABASE_FILE); c.execute('VACUUM'); c.close()"
sudo systemctl start pegaprox
```

This opens the database the way PegaProx does (encrypted or not, with its key); where the
service sets `PEGAPROX_CONFIG_DIR`, set it for the command as well.

## Drift events

Every drift scan records what deviates from the baseline. The events nobody acts on any more
are pruned once a day: only `resolved` and `superseded` ones. An open or acknowledged event,
an incident an admin confirmed, and a deviation planned under an approved change are kept
whatever their age.

| Variable | Default | Meaning |
|---|---|---|
| `PEGAPROX_DRIFT_EVENT_RETENTION_DAYS` | `365` | Days a resolved or superseded event is kept, 90 to 3650. `0` keeps them all and turns the pruning off, the cap below included. |
| `PEGAPROX_DRIFT_EVENT_CAP` | `200000` | Resolved and superseded events kept per cluster, whatever their age. Past it the oldest go first, superseded ones before resolved ones. `0` means no cap. |

The pruning runs when PegaProx starts and then once a day, in small chunks, and writes one line
to the log when it removed something. As with the metrics, the freed space is reused and the
file does not shrink on its own. The first start after the update adds an index for it to the
drift events before PegaProx serves: about a second for a few hundred thousand events, once.
