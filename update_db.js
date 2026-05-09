const db = require('./db');
const run = async () => {
    try {
        await db.query("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'SUCCESS';");
        console.log('Database updated successfully');
        process.exit(0);
    } catch (err) {
        console.error('Update failed:', err);
        process.exit(1);
    }
};
run();
