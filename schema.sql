-- Suncity Estate EDMS - PostgreSQL Schema

-- 1. Users & Staff Management
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) DEFAULT 'staff',
    permissions TEXT[], -- Array of strings: ['add_resident', 'view_logs', etc.]
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Residents Registry
CREATE TABLE residents (
    id SERIAL PRIMARY KEY,
    house_number VARCHAR(20) NOT NULL,
    street_name VARCHAR(100) NOT NULL,
    occupant_name VARCHAR(100) NOT NULL,
    occupant_type VARCHAR(20) CHECK (occupant_type IN ('Owner', 'Tenant')),
    email VARCHAR(100) UNIQUE,
    phone VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Security Personnel (Guards)
CREATE TABLE guards (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    age INTEGER,
    state_of_origin VARCHAR(50),
    lga VARCHAR(50),
    phone VARCHAR(20),
    image_url TEXT,
    resident_id INTEGER REFERENCES residents(id) ON DELETE SET NULL,
    guarantor1_name VARCHAR(100),
    guarantor1_phone VARCHAR(20),
    guarantor2_name VARCHAR(100),
    guarantor2_phone VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Audit Trail & Action Hashing
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50),
    action VARCHAR(50) NOT NULL,
    details TEXT,
    action_hash VARCHAR(64), -- SHA-256 hash for integrity
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Note: The default admin account (admin / admin123) is created securely 
-- by the application on first run if it does not already exist.
-- To manually seed users, ensure the password is hashed using bcrypt.
