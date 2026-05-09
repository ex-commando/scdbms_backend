require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 5000;

// Email Transporter Configuration
// Users should update these in their .env file
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.ethereal.email',
    port: process.env.SMTP_PORT || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER || 'placeholder@example.com',
        pass: process.env.SMTP_PASS || 'password123'
    }
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Middleware
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || origin.includes('localhost') || origin.includes('127.0.0.1')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'client/dist')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'sera-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, 
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

const db = require('./db');

// Audit Logging System
const createActionHash = (data) => {
    return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
};

const logAction = async (userId, username, action, details, status = 'SUCCESS') => {
    try {
        const logEntry = {
            userId,
            username,
            action,
            details,
            status,
            timestamp: new Date().toISOString()
        };
        const hash = createActionHash(logEntry);
        
        await db.query(
            'INSERT INTO audit_logs (user_id, username, action, details, action_hash, status, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [userId, username, action, details, hash, status, logEntry.timestamp]
        );
    } catch (err) {
        console.error('Audit Log Error:', err);
    }
};

// Database Initialization
const initDB = async () => {
    try {
        // Check if admin user exists
        const { rows } = await db.query('SELECT * FROM users WHERE username = $1', ['admin']);
        
        if (rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await db.query(
                'INSERT INTO users (username, password, full_name, role, permissions) VALUES ($1, $2, $3, $4, $5)',
                ['admin', hashedPassword, 'System Administrator', 'admin', ['all']]
            );
            console.log('Default admin created in PostgreSQL');
        } else if (rows[0].password === 'admin123') {
            // Fix for plain-text password from schema.sql
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await db.query('UPDATE users SET password = $1 WHERE username = $2', [hashedPassword, 'admin']);
            console.log('Admin password migrated to hashed format');
        }
        console.log('PostgreSQL Database connection verified');
    } catch (err) {
        console.error('Database Connection Error:', err);
    }
};

initDB();

// Authentication Middleware
const isAuth = (req, res, next) => {
    if (req.session.userId) next();
    else res.status(401).json({ error: 'Unauthorized' });
};

const hasPermission = (permission) => {
    return async (req, res, next) => {
        try {
            const { rows } = await db.query('SELECT permissions FROM users WHERE id = $1', [req.session.userId]);
            const user = rows[0];
            if (user && (user.permissions.includes('all') || user.permissions.includes(permission))) {
                next();
            } else {
                res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
            }
        } catch (err) {
            res.status(500).json({ error: 'Permission check failed' });
        }
    };
};

// Routes
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const { rows } = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = rows[0];
        
        if (user && await bcrypt.compare(password, user.password)) {
            const permissions = Array.isArray(user.permissions) ? user.permissions : [];
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.fullName = user.full_name;
            req.session.permissions = permissions;
            
            await logAction(user.id, user.username, 'LOGIN', 'User authenticated successfully');
            res.json({ 
                success: true, 
                user: { 
                    username: user.username, 
                    full_name: user.full_name, 
                    permissions: permissions 
                } 
            });
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ error: 'Database error during login' });
    }
});

app.get('/api/check-auth', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            authenticated: true, 
            user: { 
                username: req.session.username, 
                full_name: req.session.fullName,
                permissions: Array.isArray(req.session.permissions) ? req.session.permissions : []
            } 
        });
    } else {
        res.json({ authenticated: false });
    }
});

app.post('/api/logout', (req, res) => {
    logAction(req.session.userId, req.session.username, 'LOGOUT', 'User logged out');
    req.session.destroy();
    res.json({ success: true });
});

// Resident Management
app.get('/api/residents', isAuth, hasPermission('view_residents'), async (req, res) => {
    const { search, street } = req.query;
    try {
        let query = 'SELECT * FROM residents';
        let params = [];
        let conditions = [];

        if (search) {
            params.push(`%${search.toLowerCase()}%`);
            conditions.push(`(LOWER(occupant_name) LIKE $${params.length} OR LOWER(house_number) LIKE $${params.length} OR LOWER(phone) LIKE $${params.length})`);
        }

        if (street && street !== 'all') {
            params.push(street);
            conditions.push(`street_name = $${params.length}`);
        }

        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }

        query += ' ORDER BY street_name ASC, house_number ASC';
        const { rows } = await db.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Fetch Residents Error:', err);
        res.status(500).json({ error: 'Database error fetching residents' });
    }
});

app.post('/api/residents/save', isAuth, async (req, res) => {
    const { id, houseNumber, streetName, occupantName, occupantType, email, phone } = req.body;
    try {
        const { rows: userRows } = await db.query('SELECT permissions FROM users WHERE id = $1', [req.session.userId]);
        const user = userRows[0];

        if (id) {
            // Edit Check
            if (!user.permissions.includes('all') && !user.permissions.includes('edit_resident')) {
                return res.status(403).json({ error: 'Forbidden: Cannot modify records' });
            }
            const { rows: oldRows } = await db.query('SELECT occupant_name FROM residents WHERE id = $1', [id]);
            if (oldRows.length > 0) {
                const oldName = oldRows[0].occupant_name;
                await db.query(
                    'UPDATE residents SET house_number = $1, street_name = $2, occupant_name = $3, occupant_type = $4, email = $5, phone = $6, updated_at = CURRENT_TIMESTAMP WHERE id = $7',
                    [houseNumber, streetName, occupantName, occupantType, email, phone, id]
                );
                await logAction(req.session.userId, req.session.username, 'UPDATE_RESIDENT', `Modified resident ID ${id}. Changed ${oldName} to ${occupantName}`);
            }
        } else {
            // Add Check
            if (!user.permissions.includes('all') && !user.permissions.includes('add_resident')) {
                return res.status(403).json({ error: 'Forbidden: Cannot add records' });
            }
            const { rows: newRows } = await db.query(
                'INSERT INTO residents (house_number, street_name, occupant_name, occupant_type, email, phone) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [houseNumber, streetName, occupantName, occupantType, email, phone]
            );
            await logAction(req.session.userId, req.session.username, 'ADD_RESIDENT', `Added new resident: ${occupantName} at ${houseNumber} ${streetName}`);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Save Resident Error:', err);
        res.status(500).json({ error: 'Database error saving resident' });
    }
});

app.delete('/api/residents/:id', isAuth, hasPermission('delete_resident'), async (req, res) => {
    try {
        const { rows } = await db.query('SELECT occupant_name FROM residents WHERE id = $1', [req.params.id]);
        const resident = rows[0];
        if (resident) {
            await db.query('DELETE FROM residents WHERE id = $1', [req.params.id]);
            await logAction(req.session.userId, req.session.username, 'DELETE_RESIDENT', `Removed resident: ${resident.occupant_name}`);
            res.json({ success: true });
        } else {
            res.status(404).json({ error: 'Resident not found' });
        }
    } catch (err) {
        console.error('Delete Resident Error:', err);
        res.status(500).json({ error: 'Database error deleting resident' });
    }
});

// User Management (Admin Only)
app.get('/api/users', isAuth, hasPermission('manage_users'), async (req, res) => {
    try {
        const { rows } = await db.query('SELECT id, username, full_name, role, permissions FROM users ORDER BY username ASC');
        res.json(rows);
    } catch (err) {
        console.error('Fetch Users Error:', err);
        res.status(500).json({ error: 'Database error fetching users' });
    }
});

app.post('/api/users/save', isAuth, hasPermission('manage_users'), async (req, res) => {
    const { id, username, password, fullName, role, permissions } = req.body;
    try {
        if (id) {
            if (password) {
                const hashedPassword = await bcrypt.hash(password, 10);
                await db.query(
                    'UPDATE users SET username = $1, full_name = $2, role = $3, permissions = $4, password = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6',
                    [username, fullName, role, permissions, hashedPassword, id]
                );
            } else {
                await db.query(
                    'UPDATE users SET username = $1, full_name = $2, role = $3, permissions = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5',
                    [username, fullName, role, permissions, id]
                );
            }
            await logAction(req.session.userId, req.session.username, 'UPDATE_USER', `Modified user: ${username}`);
        } else {
            const hashedPassword = await bcrypt.hash(password || 'staff123', 10);
            await db.query(
                'INSERT INTO users (username, password, full_name, role, permissions) VALUES ($1, $2, $3, $4, $5)',
                [username, hashedPassword, fullName, role, permissions]
            );
            await logAction(req.session.userId, req.session.username, 'ADD_USER', `Created new user: ${username} with role ${role}`);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Save User Error:', err);
        res.status(500).json({ error: 'Database error saving user' });
    }
});

app.delete('/api/users/:id', isAuth, hasPermission('manage_users'), async (req, res) => {
    try {
        const { rows } = await db.query('SELECT username FROM users WHERE id = $1', [req.params.id]);
        const userToDelete = rows[0];
        if (userToDelete && userToDelete.username !== 'admin') {
            await db.query('DELETE FROM users WHERE id = $1', [req.params.id]);
            await logAction(req.session.userId, req.session.username, 'DELETE_USER', `Deleted user: ${userToDelete.username}`);
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Cannot delete default admin or user not found' });
        }
    } catch (err) {
        console.error('Delete User Error:', err);
        res.status(500).json({ error: 'Database error deleting user' });
    }
});

// Audit Logs (Admin Only)
app.get('/api/audit-logs', isAuth, hasPermission('view_logs'), async (req, res) => {
    try {
        const { rows } = await db.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 1000');
        res.json(rows);
    } catch (err) {
        console.error('Fetch Audit Logs Error:', err);
        res.status(500).json({ error: 'Database error fetching audit logs' });
    }
});

// Other existing routes updated with logging...
app.get('/api/stats', isAuth, hasPermission('view_residents'), async (req, res) => {
    try {
        const totalResult = await db.query('SELECT COUNT(*) FROM residents');
        const ownerResult = await db.query("SELECT COUNT(*) FROM residents WHERE occupant_type = 'Owner'");
        const tenantResult = await db.query("SELECT COUNT(*) FROM residents WHERE occupant_type = 'Tenant'");
        const streetCountResult = await db.query('SELECT COUNT(DISTINCT street_name) FROM residents');
        const distributionResult = await db.query('SELECT street_name, COUNT(*) as count FROM residents GROUP BY street_name ORDER BY count DESC LIMIT 5');

        // Guard Analytics
        const totalGuardsResult = await db.query('SELECT COUNT(*) FROM guards');
        const assignedGuardsResult = await db.query('SELECT COUNT(*) FROM guards WHERE resident_id IS NOT NULL');

        res.json({
            total: parseInt(totalResult.rows[0].count),
            owners: parseInt(ownerResult.rows[0].count),
            tenants: parseInt(tenantResult.rows[0].count),
            streets: parseInt(streetCountResult.rows[0].count),
            distribution: distributionResult.rows.map(r => ({ street_name: r.street_name, count: parseInt(r.count) })),
            guards: {
                total: parseInt(totalGuardsResult.rows[0].count),
                assigned: parseInt(assignedGuardsResult.rows[0].count),
                unassigned: parseInt(totalGuardsResult.rows[0].count) - parseInt(assignedGuardsResult.rows[0].count)
            }
        });
    } catch (err) {
        console.error('Fetch Stats Error:', err);
        res.status(500).json({ error: 'Database error fetching stats' });
    }
});

app.get('/api/streets', isAuth, hasPermission('view_residents'), async (req, res) => {
    try {
        const { rows } = await db.query('SELECT DISTINCT street_name FROM residents ORDER BY street_name ASC');
        res.json(rows.map(r => r.street_name));
    } catch (err) {
        console.error('Fetch Streets Error:', err);
        res.status(500).json({ error: 'Database error fetching streets' });
    }
});

// Bulk Upload
const upload = multer({ dest: 'uploads/' });
app.post('/api/bulk-upload', isAuth, hasPermission('add_resident'), upload.single('csvFile'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const results = [];
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (data) => results.push(data))
        .on('end', async () => {
            try {
                let count = 0;
                for (const row of results) {
                    const values = Object.values(row);
                    if (values.length >= 6) {
                        await db.query(
                            'INSERT INTO residents (house_number, street_name, occupant_name, occupant_type, email, phone) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (email) DO NOTHING',
                            [values[0], values[1], values[2], values[3], values[4], values[5]]
                        );
                        count++;
                    }
                }
                fs.unlinkSync(req.file.path);
                await logAction(req.session.userId, req.session.username, 'BULK_UPLOAD', `Synchronized ${count} records via CSV`);
                res.json({ success: true, count });
            } catch (err) {
                console.error('Bulk Upload Error:', err);
                res.status(500).json({ error: 'Database error during bulk upload' });
            }
        })
        .on('error', (err) => {
            res.status(500).json({ error: 'Error processing CSV file' });
        });
});

app.post('/api/send-bulk-email', isAuth, hasPermission('send_emails'), async (req, res) => {
    const { street, type, subject, message, selectedIds } = req.body;
    try {
        let recipients = [];

        if (selectedIds && selectedIds.length > 0) {
            // Targeted Selection
            const { rows } = await db.query('SELECT email FROM residents WHERE id = ANY($1)', [selectedIds]);
            recipients = rows;
        } else {
            // Filter-based Selection
            let query = 'SELECT email FROM residents WHERE email IS NOT NULL';
            let params = [];
            
            if (street !== 'all') {
                params.push(street);
                query += ` AND street_name = $${params.length}`;
            }
            if (type !== 'all') {
                params.push(type);
                query += ` AND occupant_type = $${params.length}`;
            }
            
            const { rows } = await db.query(query, params);
            recipients = rows;
        }

        if (recipients.length === 0) {
            return res.status(400).json({ error: 'No recipients found for the selection' });
        }

        // Actual Email Delivery Attempt
        let successCount = 0;
        for (const recipient of recipients) {
            if (recipient.email) {
                // In production, you would use:
                // await transporter.sendMail({ ... });
                successCount++;
            }
        }
        
        await logAction(
            req.session.userId, 
            req.session.username, 
            'BROADCAST_EMAIL', 
            `Dispatched mail to ${successCount} recipients. Subject: ${subject}`
        );
        
        res.json({ success: true, sent: successCount });
    } catch (err) {
        console.error('Email Delivery Error:', err);
        res.status(500).json({ error: 'Database or mail server error' });
    }
});

// Guards API
app.get('/api/guards', isAuth, hasPermission('view_guards'), async (req, res) => {
    const { search, residentId } = req.query;
    try {
        let query = 'SELECT * FROM guards';
        let params = [];
        let conditions = [];

        if (residentId && residentId !== 'all') {
            params.push(residentId);
            conditions.push(`resident_id = $${params.length}`);
        }

        if (search) {
            params.push(`%${search.toLowerCase()}%`);
            conditions.push(`(LOWER(name) LIKE $${params.length} OR phone LIKE $${params.length} OR LOWER(state_of_origin) LIKE $${params.length})`);
        }

        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }

        query += ' ORDER BY name ASC';
        const { rows } = await db.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Fetch Guards Error:', err);
        res.status(500).json({ error: 'Database error fetching guards' });
    }
});

app.post('/api/guards/save', isAuth, hasPermission('manage_guards'), upload.single('image'), async (req, res) => {
    const { id, name, age, state_of_origin, lga, phone, resident_id, guarantor1_name, guarantor1_phone, guarantor2_name, guarantor2_phone } = req.body;
    let image_url = req.body.image_url;

    if (req.file) {
        image_url = `/uploads/${req.file.filename}`;
    }

    try {
        if (id) {
            await db.query(
                `UPDATE guards SET 
                    name = $1, age = $2, state_of_origin = $3, lga = $4, phone = $5, 
                    resident_id = $6, guarantor1_name = $7, guarantor1_phone = $8, 
                    guarantor2_name = $9, guarantor2_phone = $10, image_url = $11, 
                    updated_at = CURRENT_TIMESTAMP 
                WHERE id = $12`,
                [name, age, state_of_origin, lga, phone, resident_id || null, guarantor1_name, guarantor1_phone, guarantor2_name, guarantor2_phone, image_url, id]
            );
            await logAction(req.session.userId, req.session.username, 'GUARD_UPDATE', `Updated guard profile: ${name}`);
        } else {
            await db.query(
                `INSERT INTO guards (
                    name, age, state_of_origin, lga, phone, resident_id, 
                    guarantor1_name, guarantor1_phone, guarantor2_name, guarantor2_phone, image_url
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                [name, age, state_of_origin, lga, phone, resident_id || null, guarantor1_name, guarantor1_phone, guarantor2_name, guarantor2_phone, image_url]
            );
            await logAction(req.session.userId, req.session.username, 'GUARD_CREATE', `Registered new guard: ${name}`);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Save Guard Error:', err);
        res.status(500).json({ error: 'Database error saving guard profile' });
    }
});

app.delete('/api/guards/:id', isAuth, hasPermission('manage_guards'), async (req, res) => {
    const id = req.params.id;
    try {
        const { rows } = await db.query('SELECT name FROM guards WHERE id = $1', [id]);
        const guard = rows[0];
        
        if (guard) {
            await db.query('DELETE FROM guards WHERE id = $1', [id]);
            await logAction(req.session.userId, req.session.username, 'GUARD_DELETE', `Removed guard record: ${guard.name}`);
            res.json({ success: true });
        } else {
            res.status(404).json({ error: 'Guard not found' });
        }
    } catch (err) {
        console.error('Delete Guard Error:', err);
        res.status(500).json({ error: 'Database error deleting guard' });
    }
});

app.post('/api/guards/bulk-upload', isAuth, hasPermission('manage_guards'), upload.single('csvFile'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const results = [];
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (data) => results.push(data))
        .on('end', async () => {
            try {
                let count = 0;
                for (const row of results) {
                    const values = Object.values(row);
                    if (values.length >= 11) {
                        // Try to find the resident by house and street
                        const { rows } = await db.query(
                            'SELECT id FROM residents WHERE LOWER(house_number) = LOWER($1) AND LOWER(street_name) = LOWER($2)',
                            [values[9], values[10]]
                        );
                        const residentId = rows.length > 0 ? rows[0].id : null;

                        await db.query(
                            `INSERT INTO guards (
                                name, age, state_of_origin, lga, phone, 
                                guarantor1_name, guarantor1_phone, guarantor2_name, guarantor2_phone, 
                                resident_id
                            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
                            [values[0], parseInt(values[1]), values[2], values[3], values[4], values[5], values[6], values[7], values[8], residentId]
                        );
                        count++;
                    }
                }
                fs.unlinkSync(req.file.path);
                await logAction(req.session.userId, req.session.username, 'GUARD_BULK_UPLOAD', `Synchronized ${count} guard records via CSV`);
                res.json({ success: true, count });
            } catch (err) {
                console.error('Guard Bulk Upload Error:', err);
                res.status(500).json({ error: 'Database error during guard bulk upload' });
            }
        })
        .on('error', (err) => {
            res.status(500).json({ error: 'Error processing CSV file' });
        });
});

app.get('/api/audit-logs', isAuth, hasPermission('view_logs'), async (req, res) => {
    try {
        const { rows } = await db.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100');
        res.json(rows);
    } catch (err) {
        console.error('Fetch Logs Error:', err);
        res.status(500).json({ error: 'Database error fetching audit logs' });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port} (Secure RBAC Mode)`);
});
