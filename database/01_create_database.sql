-- The MySQL container creates the database and database-scoped application
-- account from MYSQL_DATABASE, MYSQL_USER, and MYSQL_PASSWORD environment
-- variables. Keep credentials out of this SQL file.
CREATE DATABASE IF NOT EXISTS energy_iot_cve_monitor
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
