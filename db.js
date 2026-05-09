const { Pool } = require('pg');
require('dotenv').config();

// PostgreSQL Connection Pool
// Uses DATABASE_URL (Neon/production) if set, otherwise falls back to individual vars (local dev)
const poolConfig = process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false } // Required for Neon & most hosted Postgres
      }
    : {
        user: process.env.DB_USER || 'postgres',
        host: process.env.DB_HOST || 'localhost',
        database: process.env.DB_NAME || 'suncity_db',
        password: process.env.DB_PASSWORD || 'Class$312$123',
        port: process.env.DB_PORT || 5432,
      };

const pool = new Pool(poolConfig);

// Database Interface
module.exports = {
    query: (text, params) => pool.query(text, params),
    pool // Exported for transactions if needed
};
