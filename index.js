import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors({
    origin: "*",
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    credentials:true
}));
app.use(express.json());

const db = mysql.createConnection({
    host: 'bxv5bmwjr95xriibiukk-mysql.services.clever-cloud.com',
    user: 'uwl9g4bg3fo1f6ye',
    password: 'VVCTjYeHEPeGUprS7ope',
    database: 'bxv5bmwjr95xriibiukk',
    port:'3306'
});

// JWT Secret
const JWT_SECRET = 'mysecuritkey';

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" });
        }
        req.userId = decoded.id;
        next();
    });
};

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    // console.log(req.body);
    try {
        // Check if email exists
        const checkQuery = "SELECT * FROM user_login WHERE EMAIL = ?";
        db.query(checkQuery, [email], async (err, result) => {
            if (err) {
                return res.status(500).json({ message: "Database error" });
            }
            if (result.length > 0) {
                return res.status(400).json({ message: "Email already exists" });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Insert user
            const insertQuery = 'INSERT INTO user_login(EMAIL, PASS) VALUES (?, ?)';
            db.query(insertQuery, [email, hashedPassword], (err, result) => {
                if (err) {
                    return res.status(500).json({ message: "Database error" });
                }
                res.status(200).json({ message: "User registered successfully" });
            });
        });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
     console.log(email);
    try {
        const query = "SELECT * FROM user_login WHERE EMAIL = ?";
        db.query(query, [email], async (err, result) => {

            if (err) {
                return res.status(500).json({ message: "Database error" });
            }
            console.log(result);
            if (result.length === 0) {
                return res.status(401).json({ message: "Invalid credentials" });
            }

            const user = result[0];
            const validPassword = await bcrypt.compare(password, user.PASS);

            if (!validPassword) {
                return res.status(401).json({ message: "Invalid credentials" });
            }

            // Create JWT token
            const token = jwt.sign({ id: user.ID }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ token, userId: user.ID });
        });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

app.get('/auth/user', verifyToken, (req, res) => {
    const query = "SELECT ID, EMAIL FROM user_login WHERE ID = ?";
    db.query(query, [req.userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Database error" });
        }
        if (result.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json(result[0]);
    });
});

// Save code endpoint
app.post('/save-code', verifyToken, (req, res) => {
    const { title, code, language } = req.body;
    const userId = req.userId;

    const query = 'INSERT INTO saved_codes (user_id, title, code, language, created_at) VALUES (?, ?, ?, ?, NOW())';
    db.query(query, [userId, title, code, language], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Failed to save code" });
        }
        res.json({ message: "Code saved successfully" });
    });
});

// Get user's saved codes
app.get('/user-codes', verifyToken, (req, res) => {
    const query = 'SELECT * FROM saved_codes WHERE user_id = ? ORDER BY created_at DESC';
    db.query(query, [req.userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Failed to fetch codes" });
        }
        res.json(result);
    });
});

export default app;
app.listen(5000, () => {
    console.log("Server is running on port 5000");
});