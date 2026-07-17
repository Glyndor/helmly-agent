-- Rename the persisted nftables chain identifiers from the dead `lynx` brand
-- to `helmly`. Migrations 004/005 are applied history (immutable); this forward
-- migration rewrites the PRIMARY KEY values and the CHECK constraint.

ALTER TABLE nftables_state DROP CONSTRAINT nftables_state_chain_check;

UPDATE nftables_state SET chain = 'helmly-global'        WHERE chain = 'lynx-global';
UPDATE nftables_state SET chain = 'helmly-local'         WHERE chain = 'lynx-local';
UPDATE nftables_state SET chain = 'helmly-global-output' WHERE chain = 'lynx-global-output';
UPDATE nftables_state SET chain = 'helmly-local-output'  WHERE chain = 'lynx-local-output';

ALTER TABLE nftables_state ADD CONSTRAINT nftables_state_chain_check
    CHECK (chain IN ('helmly-global', 'helmly-local', 'helmly-global-output', 'helmly-local-output'));
