CREATE TABLE IF NOT EXISTS pots (
    id              TEXT        PRIMARY KEY,
    deployment_id   TEXT        NOT NULL,
    image_id        TEXT        NOT NULL,
    network_id      TEXT        NOT NULL,
    discriminator   INTEGER     NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'degraded',
    ip              TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = no hard lifetime, pot is rebuilt only on manual action or crash.
    expires_at      TIMESTAMPTZ,
    -- Fingerprint label only: "root/xxxx", SSH banner variant, etc.
    -- Full credential set lives in the agent config and is not stored.
    cred_hint       TEXT        NOT NULL DEFAULT '',
    -- NIC MAC address, used by the containment watchdog to query libvirt
    -- DomainInterfaceStats for per-pot egress counters.
    mac             TEXT        NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS deployments (
    id          TEXT        PRIMARY KEY,
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    count       INTEGER     NOT NULL,
    image_ids   TEXT[]      NOT NULL DEFAULT '{}',
    network_ids TEXT[]      NOT NULL DEFAULT '{}',
    ipam        TEXT        NOT NULL DEFAULT 'sweep',
    -- 0 = no TTL (pots survive until stopped). >0 = destroy+redeploy every N minutes.
    ttl_minutes INTEGER     NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS images (
    id       TEXT  PRIMARY KEY,
    base     TEXT  NOT NULL,
    version  TEXT  NOT NULL,
    os       TEXT  NOT NULL,
    features JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS interfaces (
    id              TEXT    PRIMARY KEY,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    link            BOOLEAN NOT NULL DEFAULT FALSE,
    mode            TEXT    NOT NULL DEFAULT 'standalone',
    aggregate_group TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS networks (
    id           TEXT    PRIMARY KEY,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    interface_id TEXT    NOT NULL,
    type         TEXT    NOT NULL DEFAULT 'native',
    vlan_id      INTEGER NOT NULL DEFAULT 0,
    subnet       TEXT    NOT NULL DEFAULT ''
);

-- Singleton row; enforced by CHECK constraint.
CREATE TABLE IF NOT EXISTS network_host (
    id              INTEGER     PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    network         TEXT        NOT NULL DEFAULT '',
    mode            TEXT        NOT NULL DEFAULT 'dhcp',
    static_ip       TEXT        NOT NULL DEFAULT '',
    static_gateway  TEXT        NOT NULL DEFAULT '',
    static_dns      TEXT        NOT NULL DEFAULT ''
);
INSERT INTO network_host (id) VALUES (1) ON CONFLICT DO NOTHING;

-- API keys: key_hash is SHA-256(raw_key) hex-encoded.
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash   TEXT        PRIMARY KEY,
    name       TEXT        NOT NULL UNIQUE,
    role       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    id      BIGSERIAL   PRIMARY KEY,
    pot_id  TEXT        NOT NULL,
    time    TIMESTAMPTZ NOT NULL,
    service TEXT        NOT NULL,
    kind    TEXT        NOT NULL,
    source  TEXT        NOT NULL,
    data    JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_pot_id_idx ON events (pot_id);
CREATE INDEX IF NOT EXISTS events_time_idx   ON events (time DESC);
