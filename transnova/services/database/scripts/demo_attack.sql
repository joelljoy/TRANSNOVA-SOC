-- Scripted run of the judge demo, for rehearsal or as a fallback. Live typing is better.
--   mysql -h <host> -P <port> -u decoy_user -p --force --table transnova_logistics < demo_attack.sql
-- --force keeps going after the expected ERROR 1142 lines.

-- 1. Enumeration: 23 tables, and no adaptive table anywhere
SHOW DATABASES;
SHOW TABLES;
SELECT COUNT(*) AS visible_tables FROM information_schema.tables WHERE table_schema = 'transnova_logistics';

-- 2. The hidden table is refused, exactly as a table that does not exist would be
SELECT * FROM shipment_archive LIMIT 3;

-- 3. Scenario A: shipment exploration reveals shipment_archive + premium_customer_records
SELECT * FROM shipments LIMIT 10;
SELECT * FROM tracking_events LIMIT 10;
SELECT c.company_name, s.tracking_no, s.status FROM shipments s JOIN customers c USING (customer_id) LIMIT 10;
SELECT SLEEP(2) AS waiting_for_reveal;
SHOW TABLES LIKE '%archive%';
SELECT * FROM shipment_archive LIMIT 3;

-- 4. Denied writes are reported as blocked, not as successful changes
CREATE TABLE unauthorized_test (id INT);
UPDATE shipments SET status = 'Delivered' WHERE shipment_id = 1;

-- 5. Scenario B: credential exploration reveals backup_credentials
SELECT * FROM api_integrations LIMIT 5;
SELECT * FROM api_credentials LIMIT 5;
SELECT SLEEP(2) AS waiting_for_reveal;
SELECT * FROM backup_credentials LIMIT 5;

-- 6. Scenario C: infrastructure exploration reveals security logs + transfer records
SELECT * FROM warehouse_access LIMIT 5;
SELECT * FROM internal_network_assets LIMIT 5;

-- 7. Scenario D: sustained interest reveals the final stage
SELECT * FROM partner_contracts LIMIT 5;
SELECT username, role, password_hash FROM admin_accounts LIMIT 5;
SELECT SLEEP(2) AS waiting_for_reveal;
SELECT * FROM executive_shipments LIMIT 5;
SELECT * FROM disaster_recovery_backup LIMIT 5;
