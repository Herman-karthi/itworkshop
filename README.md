# itworkshop
{**mandatory:
to run : - // create the users table in itworkshop database in pgadmin  before runing the login.js file //
}
 1. Introduction
 This project is a web-based College Mess Management System developed with the aim of reducing food
 wastage and improving efficiency. 
The system enables only authorized personnel such as the admin and mess secretary to register users. Each
 user is uniquely identified by their roll number and is associated with a QR code which is scanned during
 meals.
 2. Technologies Used- Backend: Node.js with PostgreSQL (pgAdmin for management)- Frontend: HTML, CSS, JavaScript- Password Security: bcrypt for hashing- QR Code: Generated per user and scanned via the admin panel
 3. User Roles and Features- Admin: Username 'admin' and password 'admin123'. Can register/delete users, view user data, and access
 the QR code scanner.- Mess Secretary: Can register clients (users).- Users: Can log in, view QR code, submit feedback, complaints, polls, and apply for leave.
 Registration is only allowed through the admin or mess secretary. On login (validated using roll number and hashed password), users access their dashboard.
 4. Database Schema
 Only the 'users' table must be manually created in pgAdmin. All other tables are created dynamically in the
 backend using db.connect(). 
SQL Code: Create 'users' Table
  CREATE TABLE users (
    id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scan_time TIMESTAMP WITH TIME ZONE
);
 5. Features Overview- QR Code Allotment: Each user gets a unique QR code after registration, visible on their dashboard.- Login: Users authenticate using roll number and password (hashed using bcrypt).- Forms: Feedback form, complaint form, meal poll form.- Polls: Users indicate if they will attend the next day's meal. Admin sees total count to prepare accordingly.- Leave Application: Users can apply for leave; admin can delete such users from active meals.- QR Code Scanning: Admin scans user's QR before meal. Double scanning is prevented to stop multiple
 entries.
 6. Food Wastage Prevention Logic
 By collecting poll responses and validating each user's QR code only once per meal, the system ensures only
 the intended number of meals are prepared and served. This prevents unauthorized access and controls
 wastage effectively.
 7. Menu Display
 A dedicated menu button on the home page displays a full month's mess timetable to all users.
 8. Conclusion
 The web application significantly improves mess management by automating user tracking, controlling food
 distribution via QR codes, and promoting accountability. It serves as a practical tool to reduce food wastage
 while ensuring fairness and transparency

 Backend Logic: login.js Code (User Registration, Login, Form Handling)
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import path from "path";
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import qr from "qr-image";
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

// Number of salt rounds for bcrypt
const SALT_ROUNDS = 10;

app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve static files from root directory

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "itworkshop",
  password: "manisainathreddy",
  port: 5432,
});
db.connect();

// Ensure assets directory exists
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir);
}

// Root route redirect to login
app.get('/', (req, res) => {
  res.redirect('/index.html');
});

// Serve user page
app.get('/user.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'user.html'));
});

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve admin login page
app.get('/adminlogin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'adminlogin.html'));
});

// Serve admin page
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Serve admin dashboard
app.get('/admin-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// Generate and store QR code for user
function generateUserQR(userData) {
  // Create a URL for the user's profile page
  const profileUrl = `http://localhost:${port}/profile.html?id=${userData.id}`;
  
  const qrPath = path.join(assetsDir, `${userData.id}_qr.png`);
  const qr_svg = qr.image(profileUrl, { type: "png" });
  const qrStream = fs.createWriteStream(qrPath);
  
  return new Promise((resolve, reject) => {
    qr_svg.pipe(qrStream);
    qrStream.on("finish", () => {
      console.log(`QR code generated and stored for user ${userData.id} with URL: ${profileUrl}`);
      resolve();
    });
    qrStream.on("error", reject);
  });
}

// Serve user page with dynamic data
app.get('/user/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Get user data from database
    const result = await db.query(
      "SELECT id, email FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    // Read the user.html file
    const userHtmlPath = path.join(__dirname, 'user.html');
    let userHtml = fs.readFileSync(userHtmlPath, 'utf8');

    // Fix the paths for CSS and assets
    userHtml = userHtml
      .replace(/href="\.\/style\.css"/g, 'href="/style.css"')
      .replace(/src="\.\/assets\//g, 'src="/assets/')
      .replace(/href="\.\/assets\//g, 'href="/assets/')
      .replace(/href="\.\//g, 'href="/')
      .replace(/src="\.\//g, 'src="/');

    // Replace both the QR code image source and its link href
    const qrCodePath = `/assets/${userId}_qr.png`;
    userHtml = userHtml.replace(
      /<a href="[^"]*"><img[^>]*><\/a>/,
      `<a href="${qrCodePath}"><img src="${qrCodePath}" alt="Your QR Code" style="max-width: 200px;"></a>`
    );

    // Add user data to the page
    userHtml = userHtml.replace(
      '</div>',
      `</div>
      <script>
        // Add user data to page
        const userData = {
          id: "${result.rows[0].id}",
          email: "${result.rows[0].email}"
        };
      </script>`
    );

    res.send(userHtml);
  } catch (error) {
    console.error("Error serving user page:", error);
    res.status(500).send('Internal server error');
  }
});

// Add user API endpoint
app.get('/api/user/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    
    const result = await db.query(
      "SELECT id, email FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API endpoints
app.post("/api/register", async (req, res) => {
  try {
    const { rollNo, email, password } = req.body;
    
    // Check if user already exists
    const checkUser = await db.query(
      "SELECT * FROM users WHERE id = $1",
      [rollNo]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists with this roll number" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert new user with hashed password
    await db.query(
      "INSERT INTO users (id, email, password) VALUES ($1, $2, $3)",
      [rollNo, email, hashedPassword]
    );

    // Generate and store QR code without sending it in response
    await generateUserQR({ id: rollNo, email });

    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Get user from database
    const result = await db.query(
      "SELECT * FROM users WHERE id = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare the provided password with the hashed password
    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.json({ 
        message: "Login successful",
        userId: user.id  // Send user ID in response
      });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create admin table if it doesn't exist
async function setupAdminTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id VARCHAR(50) PRIMARY KEY,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("Admin table created successfully");

    // Check if default admin exists
    const checkAdmin = await db.query(
      "SELECT * FROM admins WHERE id = 'admin'"
    );

    if (checkAdmin.rows.length === 0) {
      // Create default admin if not exists
      const defaultPassword = "admin123"; // You should change this in production
      const hashedPassword = await bcrypt.hash(defaultPassword, SALT_ROUNDS);
      
      await db.query(
        "INSERT INTO admins (id, email, password) VALUES ($1, $2, $3)",
        ['admin', 'admin@iitp.ac.in', hashedPassword]
      );
      console.log("Default admin user created successfully");
    }
  } catch (error) {
    console.error("Error creating admin table:", error);
  }
}

// Add last_scan_time column to users table if it doesn't exist
async function setupUsersTable() {
  try {
    await db.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS last_scan_time TIMESTAMP WITH TIME ZONE
    `);
    console.log("Users table updated with last_scan_time column");
  } catch (error) {
    console.error("Error updating users table:", error);
  }
}

// Create feedback table if it doesn't exist
async function setupFeedbackTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        feedback_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log("Feedback table created successfully");
  } catch (error) {
    console.error("Error creating feedback table:", error);
  }
}

// Create complaint table if it doesn't exist
async function setupComplaintTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS complaints (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        complaint_text TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log("Complaint table created successfully");
  } catch (error) {
    console.error("Error creating complaint table:", error);
  }
}

// Create meal confirmations table if it doesn't exist
async function setupMealConfirmationsTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS meal_confirmations (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        will_attend BOOLEAN NOT NULL,
        meal_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log("Meal confirmations table created successfully");
  } catch (error) {
    console.error("Error creating meal confirmations table:", error);
  }
}

// Initialize all tables
async function initializeTables() {
  await setupAdminTable();
  await setupUsersTable();
  await setupFeedbackTable();
  await setupComplaintTable();
  await setupMealConfirmationsTable();

}

// Call initializeTables when the server starts
initializeTables();

// Get user profile for QR scan
app.get("/api/admin/user-profile/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const adminId = req.headers['admin-id'];

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get user data
    const userResult = await db.query(
      "SELECT id, email, last_scan_time FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      user: userResult.rows[0]
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update scan time endpoint
app.post("/api/admin/update-scan", async (req, res) => {
  try {
    const { userId } = req.body;
    const adminId = req.headers['admin-id'];

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get current user data with last scan time
    const userResult = await db.query(
      "SELECT id, email, last_scan_time FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];
    const currentTime = new Date();
    
    // Check if last scan time exists and calculate time difference
    if (user.last_scan_time) {
      const lastScanTime = new Date(user.last_scan_time);
      const timeDiffInMinutes = (currentTime - lastScanTime) / (1000 * 60); // Convert to minutes
      
      // If less than 2 hours and 15 minutes (135 minutes) have passed
      if (timeDiffInMinutes < 135) {
        return res.status(400).json({ 
          error: "Cannot scan again",
          message: "User's meal is already completed. Please wait for the next meal time.",
          lastScanTime: user.last_scan_time,
          timeDiffInMinutes: Math.round(timeDiffInMinutes)
        });
      }
    }

    // Update last scan time
    const updateResult = await db.query(
      `UPDATE users 
       SET last_scan_time = CURRENT_TIMESTAMP 
       WHERE id = $1 
       RETURNING id, email, last_scan_time`,
      [userId]
    );

    res.json({
      message: "Scan time updated successfully",
      user: updateResult.rows[0]
    });
  } catch (error) {
    console.error("Error updating scan time:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin registration endpoint
app.post("/api/admin/register", async (req, res) => {
  try {
    const { username, email, password, secretKey } = req.body;

    // Verify secret key (you should change this to a secure value)
    const ADMIN_SECRET_KEY = "your-secure-admin-key";
    if (secretKey !== ADMIN_SECRET_KEY) {
      return res.status(403).json({ error: "Invalid secret key" });
    }
    
    // Check if admin already exists
    const checkAdmin = await db.query(
      "SELECT * FROM admins WHERE id = $1 OR email = $2",
      [username, email]
    );

    if (checkAdmin.rows.length > 0) {
      return res.status(400).json({ error: "Admin already exists with this username or email" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert new admin
    await db.query(
      "INSERT INTO admins (id, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "Admin registration successful" });
  } catch (error) {
    console.error("Admin registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin login endpoint
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Get admin from database
    const result = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare the provided password with the hashed password
    const admin = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (passwordMatch) {
      res.json({ 
        message: "Admin login successful",
        adminId: admin.id
      });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin data endpoint (protected)
app.get("/api/admin/data", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get all users data
    const usersResult = await db.query(
      "SELECT id, email, created_at FROM users ORDER BY created_at DESC"
    );

    res.json({
      users: usersResult.rows
    });
  } catch (error) {
    console.error("Error fetching admin data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Feedback endpoint
app.post('/api/feedback', async (req, res) => {
  try {
    const { userId, feedback } = req.body;
    
    if (!userId || !feedback) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const query = 'INSERT INTO feedback (user_id, feedback_text) VALUES ($1, $2) RETURNING *';
    const values = [userId, feedback];
    
    const result = await db.query(query, values);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error submitting feedback:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// POST /api/meal-confirmation
app.post('/api/meal-confirmation', async (req, res) => {
  // Accept 'date' from frontend and map it to 'meal_date'
  const { userId, willAttend, date } = req.body;
  if (!userId || typeof willAttend !== 'boolean' || !date) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }
  try {
    await db.query(
      `INSERT INTO meal_confirmations (user_id, will_attend, meal_date)
       VALUES ($1, $2, $3)`,
      [userId, willAttend, date]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error inserting meal confirmation:', error);
    res.status(500).json({ error: 'Database error' });
  }
});
// Complaint endpoint
app.post('/api/complaint', async (req, res) => {
  try {
    const { userId, complaint } = req.body;
    
    if (!userId || !complaint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const query = 'INSERT INTO complaints (user_id, complaint_text) VALUES ($1, $2) RETURNING *';
    const values = [userId, complaint];
    
    const result = await db.query(query, values);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error submitting complaint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all feedback for admin
app.get("/api/admin/feedback", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get all feedback with user details
    const feedbackResult = await db.query(`
      SELECT f.*, u.email as user_email 
      FROM feedback f 
      JOIN users u ON f.user_id = u.id 
      ORDER BY f.created_at DESC
    `);

    res.json({
      feedback: feedbackResult.rows
    });
  } catch (error) {
    console.error("Error fetching feedback:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
//get all poll
// Get count of "yes" for a date
app.get('/api/meal-confirmation/count', async (req, res) => {
  const { mealDate } = req.query;
  if (!mealDate) {
    return res.status(400).json({ error: 'Missing mealDate parameter' });
  }
  try {
    const result = await db.query(
      `SELECT COUNT(*) AS yes_count
       FROM meal_confirmations
       WHERE meal_date = $1 AND will_attend = TRUE`,
      [mealDate]
    );
    res.json({ count: parseInt(result.rows[0].yes_count, 10) });
  } catch (error) {
    console.error('Error fetching yes count:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get list of users who said "yes" for a date
app.get('/api/meal-confirmation/yes-users', async (req, res) => {
  const { mealDate } = req.query;
  if (!mealDate) {
    return res.status(400).json({ error: 'Missing mealDate parameter' });
  }
  try {
    // You can join with the users table to get more info if needed
    const result = await db.query(
      `SELECT user_id
       FROM meal_confirmations
       WHERE meal_date = $1 AND will_attend = TRUE`,
      [mealDate]
    );
    res.json({ users: result.rows });
  } catch (error) {
    console.error('Error fetching yes users:', error);
    res.status(500).json({ error: 'Database error' });
  }
});
// Get all complaints for admin
app.get("/api/admin/complaints", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get all complaints with user details
    const complaintsResult = await db.query(`
      SELECT c.*, u.email as user_email 
      FROM complaints c 
      JOIN users u ON c.user_id = u.id 
      ORDER BY c.created_at DESC
    `);

    res.json({
      complaints: complaintsResult.rows
    });
  } catch (error) {
    console.error("Error fetching complaints:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update complaint status
app.put("/api/admin/complaints/:id", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    const { id } = req.params;
    const { status } = req.body;

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Update complaint status
    const result = await db.query(
      "UPDATE complaints SET status = $1 WHERE id = $2 RETURNING *",
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Complaint not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating complaint:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete user API endpoint
app.delete('/api/admin/users/:userId', async (req, res) => {
    try {
        const adminId = req.headers['admin-id'];
        const userId = req.params.userId;

        // Verify admin authentication
        const adminResult = await db.query(
            "SELECT * FROM admins WHERE id = $1",
            [adminId]
        );

        if (adminResult.rows.length === 0) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // Start a transaction
        await db.query('BEGIN');

        try {
            // Delete user's QR code file
            const qrPath = path.join(assetsDir, `${userId}_qr.png`);
            if (fs.existsSync(qrPath)) {
                fs.unlinkSync(qrPath);
            }

            // Delete user's feedback
            await db.query('DELETE FROM feedback WHERE user_id = $1', [userId]);

            // Delete user's complaints
            await db.query('DELETE FROM complaints WHERE user_id = $1', [userId]);

            // Delete user's meal confirmations if the table exists
            try {
                await db.query('DELETE FROM meal_confirmations WHERE user_id = $1', [userId]);
            } catch (error) {
                console.log('Meal confirmations table might not exist, skipping deletion');
            }

            // Finally, delete the user
            const result = await db.query('DELETE FROM users WHERE id = $1 RETURNING *', [userId]);

            if (result.rows.length === 0) {
                throw new Error('User not found');
            }

            // Commit the transaction
            await db.query('COMMIT');

            res.json({ message: 'User deleted successfully' });
        } catch (error) {
            // Rollback the transaction if anything fails
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: error.message || 'Failed to delete user' });
    }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


 Frontend: HTML/CSS/JS Snippets for User and Admin Pages
 admin.html code *****
 <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - IIT Patna Mess</title>
    <link rel="stylesheet" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/html5-qrcode"></script>
    <style>
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        .container h1 {
            text-align: center;
            color: #1f2937;
            margin-bottom: 2rem;
            font-size: 2rem;
        }

        .scanner-container {
            max-width: 600px;
            margin: 0 auto 2rem auto;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .scanner-container h2 {
            text-align: center;
            color: #1f2937;
            margin-bottom: 1.5rem;
        }

        #reader {
            width: 100%;
            max-width: 500px;
            margin: 0 auto;
        }

        .scan-result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 4px;
            display: none;
        }

        .scan-success {
            background-color: #d1fae5;
            color: #065f46;
            border: 1px solid #34d399;
        }

        .scan-error {
            background-color: #fee2e2;
            color: #991b1b;
            border: 1px solid #f87171;
        }

        .user-profile {
            margin-top: 20px;
            padding: 20px;
            background-color: #f8fafc;
            border-radius: 8px;
            display: none;
        }

        .user-profile h3 {
            color: #1f2937;
            margin-bottom: 15px;
        }

        .user-info {
            margin-bottom: 15px;
        }

        .user-info p {
            margin: 5px 0;
            color: #4b5563;
        }

        .user-info strong {
            color: #1f2937;
        }

        .submit-scan {
            background-color: #2563eb;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            transition: background-color 0.3s;
        }

        .submit-scan:hover {
            background-color: #1e40af;
        }

        .submit-scan:disabled {
            background-color: #9ca3af;
            cursor: not-allowed;
        }

        .scanner-controls {
            margin-top: 20px;
            text-align: center;
        }

        .scanner-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background-color: #2563eb;
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
            font-size: 1rem;
            transition: background-color 0.3s;
        }

        .scanner-btn:hover {
            background-color: #1e40af;
        }

        .scanner-btn img {
            width: 24px;
            height: 24px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background-color: #4CAF50;
            padding: 2rem;
            border-radius: 0.5rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
            cursor: pointer;
            transition: transform 0.3s, box-shadow 0.3s;
            min-height: 150px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            font-weight: 500;
            color: rgb(5, 1, 1);
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            background-color: #96f550;
        }

        .card:nth-child(1),
        .card:nth-child(2),
        .card:nth-child(3),
        .card:nth-child(4) {
            background-color: #96f550;
            border: none;
        }

        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }

            .container {
                padding: 0 0.5rem;
            }
        }

        .registration-form {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .registration-form.active {
            display: flex;
        }

        .form-container {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 90%;
            max-width: 500px;
        }

        .form-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .form-header h2 {
            margin: 0;
            color: #1f2937;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #6b7280;
        }

        .form-group {
            margin-bottom: 1rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #4b5563;
        }

        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #e5e7eb;
            border-radius: 0.375rem;
            font-size: 1rem;
        }

        .form-group input:focus {
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .submit-btn {
            width: 100%;
            padding: 0.75rem;
            background-color: #2563eb;
            color: white;
            border: none;
            border-radius: 0.375rem;
            font-size: 1rem;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .submit-btn:hover {
            background-color: #1e40af;
        }
    </style>
</head>
<body>
    <div class="header">
        <img class="logo" src="/assets/iitp-logo.png" alt="LOGO">
        <h1>IIT-Patna-MESS-website</h1>
    </div>
    <div class="navbar">
        <a href="/admin.html"><p>Home</p></a>
        <a href="/assets/menu.pdf"><p>Menu</p></a>
        <a href="/login.html"><p>Login</p></a>
        <a href="/adminlogin.html"><p>Admin</p></a>
        <a href="/about.html"><p>About</p></a>
    </div>

    <div class="container">
        <h1>Welcome, Admin</h1>
        
        <div class="scanner-container">
            <h2>QR Code Scanner</h2>
            <div id="reader"></div>
            <div id="scanResult" class="scan-result"></div>
            
            <div id="userProfile" class="user-profile">
                <h3>User Profile</h3>
                <div class="user-info">
                    <p><strong>Roll Number:</strong> <span id="userId"></span></p>
                    <p><strong>Email:</strong> <span id="userEmail"></span></p>
                    <p><strong>Last Scan:</strong> <span id="lastScanTime"></span></p>
                </div>
                <button id="submitScan" class="submit-scan" onclick="submitScan()">Submit Scan</button>
            </div>

            <div class="scanner-controls">
                <button class="scanner-btn" onclick="toggleScanner()">
                    <img src="/assets/scanner.jpeg" alt="Scanner Icon"> Toggle Scanner
                </button>
            </div>
        </div>

        <div class="grid">
            <a href="./admin-dashboard.html" class="card">
                <div>View Users</div>
            </a>
            <a href="./admin-feedback.html" class="card">
                <div>View Feedback</div>
            </a>
            <a href="./admin-complaints.html" class="card">
                <div>View Complaints</div>
            </a>
            <a href="./poll.html" class="card">
                <div>pollresult</div>
            </a>
            <div class="card" onclick="showRegistrationForm()">
                <div>Register New user</div>
            </div>
        </div>
    </div>

    <!-- Registration Form Modal -->
    <div id="registrationForm" class="registration-form">
        <div class="form-container">
            <div class="form-header">
                <h2>Register New User</h2>
                <button class="close-btn" onclick="hideRegistrationForm()">&times;</button>
            </div>
            <form id="userRegistrationForm" onsubmit="handleRegistration(event)">
                <div class="form-group">
                    <label for="rollNo">Roll Number</label>
                    <input type="text" id="rollNo" name="rollNo" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="submit-btn">Register User</button>
            </form>
        </div>
    </div>

    <script>
        let html5QrcodeScanner = null;
        let isScannerActive = false;
        let currentUserId = null;

        // Check if admin is logged in
        if (!sessionStorage.getItem('isAdmin')) {
            window.location.href = '/adminlogin.html';
        }

        function handleClick(cardName) {
            alert(`You clicked on ${cardName}`);
        }

        function toggleScanner() {
            if (!isScannerActive) {
                startScanner();
            } else {
                stopScanner();
            }
        }

        function startScanner() {
            if (html5QrcodeScanner) {
                html5QrcodeScanner.clear();
            }

            // Reset user profile
            document.getElementById('userProfile').style.display = 'none';
            document.getElementById('submitScan').disabled = true;
            currentUserId = null;

            html5QrcodeScanner = new Html5Qrcode("reader");
            const config = { fps: 10, qrbox: { width: 250, height: 250 } };

            html5QrcodeScanner.start(
                { facingMode: "environment" },
                config,
                onScanSuccess,
                onScanFailure
            );

            isScannerActive = true;
            document.querySelector('.scanner-btn').textContent = 'Stop Scanner';
        }

        function stopScanner() {
            if (html5QrcodeScanner) {
                html5QrcodeScanner.stop().then(() => {
                    html5QrcodeScanner.clear();
                    isScannerActive = false;
                    document.querySelector('.scanner-btn').textContent = 'Start Scanner';
                }).catch(err => {
                    console.error("Error stopping scanner:", err);
                });
            }
        }

        async function onScanSuccess(decodedText) {
            try {
                // Extract user ID from the QR code URL
                const url = new URL(decodedText);
                const userId = url.searchParams.get('id');

                if (!userId) {
                    throw new Error('Invalid QR code format');
                }

                // Store current user ID
                currentUserId = userId;

                // Fetch user profile
                const response = await fetch(`/api/admin/user-profile/${userId}`, {
                    headers: {
                        'admin-id': sessionStorage.getItem('adminId')
                    }
                });

                const data = await response.json();

                if (response.ok) {
                    // Display user profile
                    document.getElementById('userId').textContent = data.user.id;
                    document.getElementById('userEmail').textContent = data.user.email;
                    document.getElementById('lastScanTime').textContent = 
                        data.user.last_scan_time ? new Date(data.user.last_scan_time).toLocaleString() : 'Never';
                    
                    // Show profile and enable submit button
                    document.getElementById('userProfile').style.display = 'block';
                    document.getElementById('submitScan').disabled = false;
                    
                    // Stop scanner
                    stopScanner();
                } else {
                    showScanResult('error', data.error || 'Failed to fetch user profile');
                }
            } catch (error) {
                showScanResult('error', 'Invalid QR code or error processing scan');
                console.error('Scan error:', error);
            }
        }

        async function submitScan() {
            if (!currentUserId) return;

            try {
                const response = await fetch('/api/admin/update-scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'admin-id': sessionStorage.getItem('adminId')
                    },
                    body: JSON.stringify({ userId: currentUserId })
                });

                const data = await response.json();

                if (response.ok) {
                    showScanResult('success', `Successfully updated scan time for user: ${data.user.email}`);
                    // Update last scan time in profile
                    document.getElementById('lastScanTime').textContent = 
                        new Date(data.user.last_scan_time).toLocaleString();
                    // Disable submit button
                    document.getElementById('submitScan').disabled = true;
                } else {
                    // Handle time difference error
                    if (response.status === 400 && data.error === "Cannot scan again") {
                        const lastScan = new Date(data.lastScanTime).toLocaleString();
                        const timeLeft = Math.round(135 - data.timeDiffInMinutes);
                        showScanResult('error', 
                            `${data.message}\nLast scan: ${lastScan}\nTime remaining: ${timeLeft} minutes`);
                    } else {
                        showScanResult('error', data.error || 'Failed to update scan time');
                    }
                }
            } catch (error) {
                showScanResult('error', 'Error updating scan time');
                console.error('Submit error:', error);
            }
        }

        function onScanFailure(error) {
            // Handle scan failure silently
            console.warn(`QR scan failed: ${error}`);
        }

        function showScanResult(type, message) {
            const resultDiv = document.getElementById('scanResult');
            // Replace newlines with <br> tags for proper display
            resultDiv.innerHTML = message.replace(/\n/g, '<br>');
            resultDiv.className = `scan-result scan-${type}`;
            resultDiv.style.display = 'block';

            // Hide the result after 5 seconds for error messages
            const hideDelay = type === 'error' ? 5000 : 3000;
            setTimeout(() => {
                resultDiv.style.display = 'none';
            }, hideDelay);
        }

        // Clean up scanner when page is unloaded
        window.addEventListener('beforeunload', () => {
            if (html5QrcodeScanner) {
                html5QrcodeScanner.stop().catch(err => {
                    console.error("Error stopping scanner:", err);
                });
            }
        });

        function showRegistrationForm() {
            document.getElementById('registrationForm').classList.add('active');
        }

        function hideRegistrationForm() {
            document.getElementById('registrationForm').classList.remove('active');
        }

        async function handleRegistration(event) {
            event.preventDefault();
            
            const rollNo = document.getElementById('rollNo').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ rollNo, email, password })
                });

                const data = await response.json();

                if (response.ok) {
                    alert('User registered successfully!');
                    hideRegistrationForm();
                    document.getElementById('userRegistrationForm').reset();
                } else {
                    alert(data.error || 'Registration failed');
                }
            } catch (error) {
                console.error('Registration error:', error);
                alert('An error occurred during registration');
            }
        }
    </script>
</body>
</html>
user.html code****
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agency</title>
  <link rel="stylesheet" href="./style.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;700&display=swap" rel="stylesheet">
  <style>
    .qr-box img {
        cursor: pointer;
        max-width: 200px;
        transition: transform 0.3s ease;
    }
    .qr-box img:hover {
        transform: scale(1.05);
    }
  </style>
</head>

<body>
    <div class="header">
        <img class="logo" src="./assets/iitp-logo.png" alt="LOGO">
        <h1>IIT-Patna-MESS-website</h1>
    </div>
    <div class="navbar">
        <a href="./user.html"> <p>home</p> </a>
        <a href="./assets/menu.pdf"> <p>menu</p> </a>
        <a href="./forms.html"><p>forms</p></a>
        <a id="profileLink" href="#"><p>profile</p></a>
        <a href="./about.html"> <p>about</p> </a>
    </div>

    <main>
        <div class="content-row">
            <!-- QR Box -->
            <div class="qr-box">
                <h2>QR-CODE</h2>
                <a id="qrLink" href="#" target="_blank">
                    <img id="userQrCode" alt="QR Code">
                </a>
            </div>
    
            <!-- Meal confirmation form -->
            <div class="meal-form">
                <h2>Meal Confirmation</h2>
                <form id="mealForm">
                    <p>Do you want to attend tomorrow's meal?</p>
                    <label>
                        <input type="radio" name="meal" value="yes"> Yes
                    </label>
                    <label>
                        <input type="radio" name="meal" value="no" checked> No
                    </label>
                    <br><br>
                    <button type="submit">Submit</button>
                </form>
            </div>

            <div class="qr-box">
                <h2>Weekday Timings</h2>
                <p>Breakfast: 8:00 – 10:00</p>
                <p>Lunch: 12:30 – 2:00</p>
                <p>Dinner: 7:45 – 10:00</p>
              </div>
        
              <!-- Weekend Timings Box -->
              <div class="qr-box">
                <h2>Weekend Timings</h2>
                <p>Breakfast: 8:30 – 10:30</p>
                <p>Lunch: 1:00 – 2:30</p>
                <p>Dinner: 7:45 – 10:00</p>
              </div>
        </div>
    </main>
    <div class="datetime-box">
        <p id="datetime"></p>
    </div>
    
    < 
    <script>
        // Check if user is logged in
        function checkLogin() {
            const userId = sessionStorage.getItem('userId');
            if (!userId) {
                window.location.href = '/login.html';
                return;
            }
            return userId;
        }

        // Update profile link and QR code
        function updateUserElements() {
            const userId = checkLogin();
            if (userId) {
                // Update profile link
                const profileLink = document.getElementById('profileLink');
                profileLink.href = `/profile.html?id=${userId}`;

                // Update QR code image and link
                const qrPath = `/assets/${userId}_qr.png`;
                const userQrCode = document.getElementById('userQrCode');
                const qrLink = document.getElementById('qrLink');
                
                userQrCode.src = qrPath;
                qrLink.href = qrPath;
            }
        }

        function updateDateTime() {
            const now = new Date();
            const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
            const date = now.toLocaleDateString(undefined, options);
            const time = now.toLocaleTimeString();
            document.getElementById("datetime").textContent = `${date} | ${time}`;
        }

        // Meal form submission handler
        async function handleMealFormSubmit(event) {
            event.preventDefault();
            
            const userId = sessionStorage.getItem('userId');
            if (!userId) {
                alert('Please login first');
                window.location.href = '/login.html';
                return;
            }

            const mealChoice = document.querySelector('input[name="meal"]:checked').value;
            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            const date = tomorrow.toISOString().split('T')[0]; // Format: YYYY-MM-DD

            try {
                const response = await fetch('/api/meal-confirmation', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        userId,
                        date,
                        willAttend: mealChoice === 'yes'
                    })
                });

                if (!response.ok) {
                    throw new Error('Failed to submit meal confirmation');
                }

                const result = await response.json();
                alert('Meal confirmation submitted successfully!');
                
                // Reset form
                event.target.reset();
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to submit meal confirmation. Please try again.');
            }
        }
    
        // Initialize page
        updateUserElements();
        updateDateTime();
        setInterval(updateDateTime, 1000);

        // Add meal form event listener
        const mealForm = document.getElementById('mealForm');
        if (mealForm) {
            mealForm.addEventListener('submit', handleMealFormSubmit);
        }
    </script>
</body>

</html>
