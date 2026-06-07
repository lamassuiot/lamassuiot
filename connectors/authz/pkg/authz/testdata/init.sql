-- IoT Domain Example Database Schema
-- This demonstrates an IoT authorization hierarchy:
-- Organization -> Building -> Gateway -> Device

-- Organizations table
CREATE TABLE organizations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Buildings table (belongs to organization)
CREATE TABLE buildings (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) REFERENCES organizations(id) ON DELETE CASCADE,
    manager_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IoT Gateways table (belongs to building)
CREATE TABLE iot_gateways (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    building_id VARCHAR(255) REFERENCES buildings(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IoT Devices table (belongs to gateway)
CREATE TABLE iot_devices (
    device_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    gateway_id VARCHAR(255) REFERENCES iot_gateways(id) ON DELETE CASCADE,
    assigned_technician_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for foreign key lookups
CREATE INDEX idx_devices_gateway ON iot_devices(gateway_id);
CREATE INDEX idx_devices_technician ON iot_devices(assigned_technician_id);
CREATE INDEX idx_gateways_building ON iot_gateways(building_id);
CREATE INDEX idx_buildings_org ON buildings(organization_id);
CREATE INDEX idx_buildings_manager ON buildings(manager_id);
CREATE INDEX idx_orgs_owner ON organizations(owner_id);

-- Sample data for testing
INSERT INTO organizations (id, name, owner_id) VALUES
    ('org-1', 'Acme Corp', 'user-alice'),
    ('org-2', 'Beta Industries', 'user-bob');

INSERT INTO buildings (id, name, organization_id, manager_id) VALUES
    ('building-1', 'HQ Building', 'org-1', 'user-charlie'),
    ('building-2', 'Factory A', 'org-1', 'user-dave'),
    ('building-3', 'Office B', 'org-2', 'user-eve');

INSERT INTO iot_gateways (id, name, building_id) VALUES
    ('gateway-1', 'HQ Gateway 1', 'building-1'),
    ('gateway-2', 'HQ Gateway 2', 'building-1'),
    ('gateway-3', 'Factory Gateway', 'building-2'),
    ('gateway-4', 'Office Gateway', 'building-3');

INSERT INTO iot_devices (device_id, name, gateway_id, assigned_technician_id) VALUES
    ('device-1', 'Temperature Sensor 1', 'gateway-1', 'user-frank'),
    ('device-2', 'Temperature Sensor 2', 'gateway-1', 'user-frank'),
    ('device-3', 'Humidity Sensor', 'gateway-2', 'user-george'),
    ('device-4', 'Factory Sensor', 'gateway-3', NULL),
    ('device-5', 'Office Sensor', 'gateway-4', 'user-frank');
