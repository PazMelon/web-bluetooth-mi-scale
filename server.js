require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// Create connection pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'e57!@HJpANqqb92*',
    database: 'srcb-clinic',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// GET Student by ID Number (for kiosk input)
app.get('/api/student/:id_number', async (req, res) => {
    try {
        const idNumber = req.params.id_number;
        const [rows] = await pool.query(
            'SELECT profile_id, id_number, first_name, last_name, status FROM student_profile WHERE id_number = ? LIMIT 1',
            [idNumber]
        );

        if (rows.length > 0) {
            res.json({ success: true, student: rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'Student ID not found in database.' });
        }
    } catch (error) {
        console.error('Error fetching student:', error);
        res.status(500).json({ success: false, message: 'Server error retrieving student data.' });
    }
});

// POST Vitals
app.post('/api/vitals', async (req, res) => {
    try {
        const { user_id, weight_kg, heart_rate } = req.body;
        
        if (!user_id || !weight_kg) {
            return res.status(400).json({ success: false, message: 'user_id and weight_kg are required.' });
        }

        const hrParam = heart_rate ? parseInt(heart_rate) : null;
        const weightParam = parseFloat(weight_kg).toFixed(2);

        const [result] = await pool.query(
            'INSERT INTO iot_vitals (user_id, weight_kg, heart_rate) VALUES (?, ?, ?)',
            [user_id, weightParam, hrParam]
        );

        res.json({ success: true, message: 'Vitals saved successfully', insertId: result.insertId });
    } catch (error) {
        console.error('Error saving vitals:', error);
        res.status(500).json({ success: false, message: 'Server error saving vitals.' });
    }
});

// Handle graceful shutdown
process.on('SIGINT', async () => {
    await pool.end();
    process.exit();
});

app.listen(PORT, () => {
    console.log(`SRCB Clinic Kiosk API running on http://localhost:${PORT}`);
});
