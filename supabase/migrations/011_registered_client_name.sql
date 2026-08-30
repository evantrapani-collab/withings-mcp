-- Store the client_name an app supplies at dynamic registration (RFC 7591).
--
-- The first-party consent screen shown before the Withings hop can otherwise
-- only identify the requesting app by its raw client_id (a UUID), which gives
-- the user nothing to recognize. Persisting client_name lets the consent
-- screen show a human-readable name instead.
--
-- Nullable: client_name is optional per RFC 7591, and the column must be safe
-- to add to a live table with existing registered_clients rows.
ALTER TABLE registered_clients ADD COLUMN IF NOT EXISTS client_name TEXT;
