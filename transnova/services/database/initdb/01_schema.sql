-- TransNova Logistics: fictional internal database for the deception lab.
-- 23 operational / sensitive-looking tables, plus 8 adaptive decoy tables that the
-- attacker account cannot see until the adaptive controller grants them.
-- Everything here is synthetic. Nothing in this schema relates to a real company.

CREATE DATABASE IF NOT EXISTS transnova_logistics
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE transnova_logistics;

-- ---------------------------------------------------------------- B. Logistics operations
CREATE TABLE warehouses (
  warehouse_id   INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  code           CHAR(6) NOT NULL UNIQUE,
  name           VARCHAR(80) NOT NULL,
  city           VARCHAR(60) NOT NULL,
  state          VARCHAR(40) NOT NULL,
  capacity_units INT UNSIGNED NOT NULL,
  status         ENUM('Active','Maintenance','Closed') NOT NULL DEFAULT 'Active',
  opened_on      DATE NOT NULL
) ENGINE=InnoDB;

CREATE TABLE employees (
  employee_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  employee_no  CHAR(8) NOT NULL UNIQUE,
  first_name   VARCHAR(40) NOT NULL,
  last_name    VARCHAR(40) NOT NULL,
  email        VARCHAR(120) NOT NULL UNIQUE,
  department   ENUM('Operations','Finance','IT','Security','Customer Support','Fleet','Executive') NOT NULL,
  job_title    VARCHAR(80) NOT NULL,
  warehouse_id INT UNSIGNED NULL,
  manager_id   INT UNSIGNED NULL,
  hired_on     DATE NOT NULL,
  status       ENUM('Active','On Leave','Terminated') NOT NULL DEFAULT 'Active',
  CONSTRAINT fk_emp_wh  FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
  CONSTRAINT fk_emp_mgr FOREIGN KEY (manager_id) REFERENCES employees(employee_id),
  INDEX idx_emp_dept (department)
) ENGINE=InnoDB;

CREATE TABLE vehicles (
  vehicle_id       INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  registration_no  VARCHAR(16) NOT NULL UNIQUE,
  vehicle_type     ENUM('Van','Light Truck','Heavy Truck','Refrigerated Truck') NOT NULL,
  capacity_kg      INT UNSIGNED NOT NULL,
  home_warehouse_id INT UNSIGNED NOT NULL,
  status           ENUM('Available','In Service','Maintenance','Retired') NOT NULL DEFAULT 'Available',
  last_service_on  DATE NULL,
  CONSTRAINT fk_veh_wh FOREIGN KEY (home_warehouse_id) REFERENCES warehouses(warehouse_id)
) ENGINE=InnoDB;

CREATE TABLE delivery_agents (
  agent_id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  employee_id     INT UNSIGNED NOT NULL UNIQUE,
  license_no      VARCHAR(20) NOT NULL UNIQUE,
  license_expiry  DATE NOT NULL,
  vehicle_id      INT UNSIGNED NULL,
  rating          DECIMAL(2,1) NOT NULL,
  status          ENUM('On Duty','Off Duty','Suspended') NOT NULL DEFAULT 'Off Duty',
  CONSTRAINT fk_agent_emp FOREIGN KEY (employee_id) REFERENCES employees(employee_id),
  CONSTRAINT fk_agent_veh FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
) ENGINE=InnoDB;

CREATE TABLE routes (
  route_id            INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  route_code          CHAR(9) NOT NULL UNIQUE,
  origin_warehouse_id INT UNSIGNED NOT NULL,
  dest_warehouse_id   INT UNSIGNED NOT NULL,
  distance_km         INT UNSIGNED NOT NULL,
  est_hours           DECIMAL(4,1) NOT NULL,
  risk_level          ENUM('Low','Medium','High') NOT NULL DEFAULT 'Low',
  active              TINYINT(1) NOT NULL DEFAULT 1,
  CONSTRAINT fk_route_o FOREIGN KEY (origin_warehouse_id) REFERENCES warehouses(warehouse_id),
  CONSTRAINT fk_route_d FOREIGN KEY (dest_warehouse_id) REFERENCES warehouses(warehouse_id)
) ENGINE=InnoDB;

CREATE TABLE inventory (
  inventory_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  warehouse_id  INT UNSIGNED NOT NULL,
  sku           VARCHAR(16) NOT NULL,
  description   VARCHAR(120) NOT NULL,
  quantity      INT UNSIGNED NOT NULL,
  reorder_level INT UNSIGNED NOT NULL,
  updated_at    DATETIME NOT NULL,
  UNIQUE KEY uq_inv (warehouse_id, sku),
  CONSTRAINT fk_inv_wh FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
) ENGINE=InnoDB;

CREATE TABLE maintenance_records (
  maintenance_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  vehicle_id     INT UNSIGNED NOT NULL,
  service_date   DATE NOT NULL,
  service_type   ENUM('Routine','Brake','Engine','Tyres','Refrigeration','Inspection') NOT NULL,
  cost_inr       DECIMAL(10,2) NOT NULL,
  odometer_km    INT UNSIGNED NOT NULL,
  notes          VARCHAR(200) NULL,
  CONSTRAINT fk_maint_veh FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- C. Business operations
CREATE TABLE shipping_partners (
  partner_id    INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  partner_name  VARCHAR(80) NOT NULL UNIQUE,
  partner_type  ENUM('Air Freight','Ocean Freight','Rail','Last Mile','Customs Broker') NOT NULL,
  contact_email VARCHAR(120) NOT NULL,
  country       VARCHAR(40) NOT NULL,
  status        ENUM('Active','Suspended','Prospect') NOT NULL DEFAULT 'Active'
) ENGINE=InnoDB;

CREATE TABLE api_integrations (
  integration_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  partner_id     INT UNSIGNED NOT NULL,
  system_name    VARCHAR(60) NOT NULL,
  base_url       VARCHAR(160) NOT NULL,
  auth_type      ENUM('API Key','OAuth2 Client','mTLS','HMAC') NOT NULL,
  environment    ENUM('production','staging') NOT NULL,
  last_sync_at   DATETIME NULL,
  status         ENUM('Healthy','Degraded','Disabled') NOT NULL DEFAULT 'Healthy',
  CONSTRAINT fk_integ_partner FOREIGN KEY (partner_id) REFERENCES shipping_partners(partner_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- A. Customers and shipments
CREATE TABLE customers (
  customer_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  account_no   CHAR(10) NOT NULL UNIQUE,
  company_name VARCHAR(120) NOT NULL,
  contact_name VARCHAR(80) NOT NULL,
  email        VARCHAR(120) NOT NULL,
  phone        VARCHAR(24) NOT NULL,
  tier         ENUM('Standard','Business','Premium') NOT NULL DEFAULT 'Standard',
  credit_limit_inr DECIMAL(12,2) NOT NULL,
  created_at   DATETIME NOT NULL,
  INDEX idx_cust_tier (tier)
) ENGINE=InnoDB;

CREATE TABLE delivery_addresses (
  address_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  customer_id INT UNSIGNED NOT NULL,
  label       VARCHAR(40) NOT NULL,
  line1       VARCHAR(120) NOT NULL,
  city        VARCHAR(60) NOT NULL,
  state       VARCHAR(40) NOT NULL,
  postal_code VARCHAR(10) NOT NULL,
  is_default  TINYINT(1) NOT NULL DEFAULT 0,
  CONSTRAINT fk_addr_cust FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
) ENGINE=InnoDB;

CREATE TABLE shipments (
  shipment_id         INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  tracking_no         CHAR(14) NOT NULL UNIQUE,
  customer_id         INT UNSIGNED NOT NULL,
  address_id          INT UNSIGNED NOT NULL,
  origin_warehouse_id INT UNSIGNED NOT NULL,
  route_id            INT UNSIGNED NULL,
  agent_id            INT UNSIGNED NULL,
  partner_id          INT UNSIGNED NULL,
  status              ENUM('Pending','In Transit','Delivered','Delayed','Failed Delivery','Under Investigation') NOT NULL,
  weight_kg           DECIMAL(8,2) NOT NULL,
  declared_value_inr  DECIMAL(12,2) NOT NULL,
  created_at          DATETIME NOT NULL,
  promised_on         DATE NOT NULL,
  delivered_at        DATETIME NULL,
  CONSTRAINT fk_ship_cust  FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
  CONSTRAINT fk_ship_addr  FOREIGN KEY (address_id) REFERENCES delivery_addresses(address_id),
  CONSTRAINT fk_ship_wh    FOREIGN KEY (origin_warehouse_id) REFERENCES warehouses(warehouse_id),
  CONSTRAINT fk_ship_route FOREIGN KEY (route_id) REFERENCES routes(route_id),
  CONSTRAINT fk_ship_agent FOREIGN KEY (agent_id) REFERENCES delivery_agents(agent_id),
  CONSTRAINT fk_ship_part  FOREIGN KEY (partner_id) REFERENCES shipping_partners(partner_id),
  INDEX idx_ship_status (status),
  INDEX idx_ship_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE shipment_items (
  item_id     INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  shipment_id INT UNSIGNED NOT NULL,
  sku         VARCHAR(16) NOT NULL,
  description VARCHAR(120) NOT NULL,
  quantity    INT UNSIGNED NOT NULL,
  unit_value_inr DECIMAL(10,2) NOT NULL,
  CONSTRAINT fk_item_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id)
) ENGINE=InnoDB;

CREATE TABLE tracking_events (
  tracking_event_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  shipment_id INT UNSIGNED NOT NULL,
  event_time  DATETIME NOT NULL,
  location    VARCHAR(80) NOT NULL,
  status      VARCHAR(40) NOT NULL,
  remarks     VARCHAR(160) NULL,
  CONSTRAINT fk_track_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id),
  INDEX idx_track_time (shipment_id, event_time)
) ENGINE=InnoDB;

CREATE TABLE invoices (
  invoice_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  invoice_no  CHAR(12) NOT NULL UNIQUE,
  customer_id INT UNSIGNED NOT NULL,
  shipment_id INT UNSIGNED NOT NULL,
  amount_inr  DECIMAL(12,2) NOT NULL,
  tax_inr     DECIMAL(12,2) NOT NULL,
  issued_on   DATE NOT NULL,
  due_on      DATE NOT NULL,
  status      ENUM('Issued','Paid','Overdue','Disputed') NOT NULL,
  CONSTRAINT fk_inv_cust FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
  CONSTRAINT fk_inv_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id)
) ENGINE=InnoDB;

CREATE TABLE payments (
  payment_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  invoice_id  INT UNSIGNED NOT NULL,
  paid_on     DATE NOT NULL,
  amount_inr  DECIMAL(12,2) NOT NULL,
  method      ENUM('NEFT','RTGS','UPI','Cheque') NOT NULL,
  reference   VARCHAR(24) NOT NULL UNIQUE,
  CONSTRAINT fk_pay_inv FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id)
) ENGINE=InnoDB;

CREATE TABLE dispatch_records (
  dispatch_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  shipment_id  INT UNSIGNED NOT NULL,
  route_id     INT UNSIGNED NOT NULL,
  agent_id     INT UNSIGNED NOT NULL,
  vehicle_id   INT UNSIGNED NOT NULL,
  dispatched_at DATETIME NOT NULL,
  status       ENUM('Scheduled','Departed','Completed','Cancelled') NOT NULL,
  CONSTRAINT fk_disp_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id),
  CONSTRAINT fk_disp_route FOREIGN KEY (route_id) REFERENCES routes(route_id),
  CONSTRAINT fk_disp_agent FOREIGN KEY (agent_id) REFERENCES delivery_agents(agent_id),
  CONSTRAINT fk_disp_veh FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
) ENGINE=InnoDB;

CREATE TABLE support_tickets (
  ticket_id   INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  ticket_no   CHAR(11) NOT NULL UNIQUE,
  customer_id INT UNSIGNED NOT NULL,
  shipment_id INT UNSIGNED NULL,
  assigned_to INT UNSIGNED NULL,
  category    ENUM('Delay','Damage','Billing','Lost Parcel','General') NOT NULL,
  priority    ENUM('Low','Normal','High','Urgent') NOT NULL,
  status      ENUM('Open','In Progress','Resolved','Closed') NOT NULL,
  subject     VARCHAR(140) NOT NULL,
  opened_at   DATETIME NOT NULL,
  CONSTRAINT fk_tkt_cust FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
  CONSTRAINT fk_tkt_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id),
  CONSTRAINT fk_tkt_emp  FOREIGN KEY (assigned_to) REFERENCES employees(employee_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- D. Sensitive-looking decoys
-- All values are fake and marked by construction (example domains, TEST prefixes, and
-- addresses from documentation ranges). They unlock nothing.
CREATE TABLE api_credentials (
  credential_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  integration_id INT UNSIGNED NOT NULL,
  key_name       VARCHAR(60) NOT NULL,
  api_key        VARCHAR(80) NOT NULL,
  api_secret     VARCHAR(80) NOT NULL,
  rotated_on     DATE NOT NULL,
  owner_employee_id INT UNSIGNED NOT NULL,
  CONSTRAINT fk_cred_integ FOREIGN KEY (integration_id) REFERENCES api_integrations(integration_id),
  CONSTRAINT fk_cred_owner FOREIGN KEY (owner_employee_id) REFERENCES employees(employee_id)
) ENGINE=InnoDB;

CREATE TABLE admin_accounts (
  admin_id      INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  employee_id   INT UNSIGNED NOT NULL,
  username      VARCHAR(40) NOT NULL UNIQUE,
  password_hash CHAR(64) NOT NULL,
  role          ENUM('dba','sysadmin','finance_admin','ops_admin') NOT NULL,
  mfa_enabled   TINYINT(1) NOT NULL,
  last_login_at DATETIME NULL,
  CONSTRAINT fk_admin_emp FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
) ENGINE=InnoDB;

CREATE TABLE warehouse_access (
  access_id    INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  warehouse_id INT UNSIGNED NOT NULL,
  employee_id  INT UNSIGNED NOT NULL,
  badge_no     CHAR(10) NOT NULL UNIQUE,
  door_pin     CHAR(6) NOT NULL,
  access_level ENUM('Dock','Floor','Cage','Vault') NOT NULL,
  valid_until  DATE NOT NULL,
  CONSTRAINT fk_wa_wh FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
  CONSTRAINT fk_wa_emp FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
) ENGINE=InnoDB;

CREATE TABLE partner_contracts (
  contract_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  partner_id   INT UNSIGNED NOT NULL,
  contract_no  CHAR(12) NOT NULL UNIQUE,
  annual_value_inr DECIMAL(14,2) NOT NULL,
  rebate_percent DECIMAL(4,2) NOT NULL,
  signed_on    DATE NOT NULL,
  expires_on   DATE NOT NULL,
  confidential_terms VARCHAR(200) NOT NULL,
  CONSTRAINT fk_pc_partner FOREIGN KEY (partner_id) REFERENCES shipping_partners(partner_id)
) ENGINE=InnoDB;

CREATE TABLE internal_network_assets (
  asset_id    INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  hostname    VARCHAR(60) NOT NULL UNIQUE,
  ip_address  VARCHAR(15) NOT NULL,
  role        VARCHAR(60) NOT NULL,
  environment ENUM('prod','dr','corp') NOT NULL,
  warehouse_id INT UNSIGNED NULL,
  os_version  VARCHAR(40) NOT NULL,
  CONSTRAINT fk_net_wh FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- Adaptive decoy tables
-- No grant to decoy_user at start. The adaptive controller reveals them one by one.
CREATE TABLE shipment_archive (
  archive_id    INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  shipment_id   INT UNSIGNED NOT NULL,
  tracking_no   CHAR(14) NOT NULL,
  customer_name VARCHAR(120) NOT NULL,
  final_status  VARCHAR(40) NOT NULL,
  archived_on   DATE NOT NULL,
  storage_ref   VARCHAR(60) NOT NULL,
  CONSTRAINT fk_arch_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id)
) ENGINE=InnoDB;

CREATE TABLE premium_customer_records (
  record_id     INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  customer_id   INT UNSIGNED NOT NULL,
  account_manager VARCHAR(80) NOT NULL,
  annual_spend_inr DECIMAL(14,2) NOT NULL,
  negotiated_discount DECIMAL(4,2) NOT NULL,
  notes         VARCHAR(200) NOT NULL,
  CONSTRAINT fk_prem_cust FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
) ENGINE=InnoDB;

CREATE TABLE restricted_routes (
  restricted_route_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  route_id     INT UNSIGNED NOT NULL,
  cargo_class  ENUM('High Value','Pharma','Defence Spares','Bullion') NOT NULL,
  escort_required TINYINT(1) NOT NULL,
  checkpoint_notes VARCHAR(200) NOT NULL,
  CONSTRAINT fk_rr_route FOREIGN KEY (route_id) REFERENCES routes(route_id)
) ENGINE=InnoDB;

CREATE TABLE backup_credentials (
  backup_cred_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  system_name  VARCHAR(60) NOT NULL,
  account      VARCHAR(40) NOT NULL,
  secret_value VARCHAR(80) NOT NULL,
  vault_path   VARCHAR(100) NOT NULL,
  last_verified DATE NOT NULL
) ENGINE=InnoDB;

CREATE TABLE warehouse_security_logs (
  log_id       INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  warehouse_id INT UNSIGNED NOT NULL,
  badge_no     CHAR(10) NOT NULL,
  door         VARCHAR(40) NOT NULL,
  logged_at    DATETIME NOT NULL,
  result       ENUM('Granted','Denied','Forced') NOT NULL,
  CONSTRAINT fk_wsl_wh FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
) ENGINE=InnoDB;

CREATE TABLE internal_transfer_records (
  transfer_id  INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  from_warehouse_id INT UNSIGNED NOT NULL,
  to_warehouse_id   INT UNSIGNED NOT NULL,
  sku          VARCHAR(16) NOT NULL,
  quantity     INT UNSIGNED NOT NULL,
  approved_by  INT UNSIGNED NOT NULL,
  transferred_on DATE NOT NULL,
  CONSTRAINT fk_itr_from FOREIGN KEY (from_warehouse_id) REFERENCES warehouses(warehouse_id),
  CONSTRAINT fk_itr_to   FOREIGN KEY (to_warehouse_id) REFERENCES warehouses(warehouse_id),
  CONSTRAINT fk_itr_emp  FOREIGN KEY (approved_by) REFERENCES employees(employee_id)
) ENGINE=InnoDB;

CREATE TABLE executive_shipments (
  exec_shipment_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  shipment_id  INT UNSIGNED NOT NULL,
  executive_employee_id INT UNSIGNED NOT NULL,
  purpose      VARCHAR(120) NOT NULL,
  handling_notes VARCHAR(200) NOT NULL,
  CONSTRAINT fk_exec_ship FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id),
  CONSTRAINT fk_exec_emp  FOREIGN KEY (executive_employee_id) REFERENCES employees(employee_id)
) ENGINE=InnoDB;

CREATE TABLE disaster_recovery_backup (
  dr_id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  asset_id     INT UNSIGNED NOT NULL,
  backup_set   VARCHAR(60) NOT NULL,
  location     VARCHAR(100) NOT NULL,
  encryption_key_ref VARCHAR(80) NOT NULL,
  last_success_at DATETIME NOT NULL,
  CONSTRAINT fk_dr_asset FOREIGN KEY (asset_id) REFERENCES internal_network_assets(asset_id)
) ENGINE=InnoDB;
