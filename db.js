const { Pool } = require('pg');
require('dotenv').config();

// PostgreSQL Connection Pool
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'suncity_db',
    password: process.env.DB_PASSWORD || 'Class$312$123',
    port: process.env.DB_PORT || 5432,
});

// Database Interface
module.exports = {
    query: (text, params) => pool.query(text, params),
    pool // Exported for transactions if needed
};
