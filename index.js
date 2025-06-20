const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { OAuth2Client } = require('google-auth-library');
const helmet = require('helmet');
const morgan = require('morgan');
const pool = require("./db");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

dotenv.config();

const userRouter = require("./routers/user");
const app = express();

// Initialize Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware
app.use(helmet({
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://accounts.google.com"],
      connectSrc: ["'self'", process.env.CORS_ORIGIN],
      imgSrc: ["'self'", "data:", "https://lh3.googleusercontent.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      frameSrc: ["'self'", "https://accounts.google.com"]
    }
  }
}));





// app.use(cors({
//   origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));



app.use(cors({
  origin: [
    process.env.CORS_ORIGIN, 
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  exposedHeaders: ['set-cookie']
}));




app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(morgan('dev'));

// Token verification middleware




const authenticateToken = async (req, res, next) => {
  // Check cookies first, then Authorization header
  const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const [user] = await pool.execute(
      "SELECT id, email, name, picture FROM users WHERE id = ?",
      [decoded.userId]
    );
    
    if (!user[0]) {
      return res.status(403).json({ error: 'User not found' });
    }

    req.user = user[0];
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    
    // Clear invalid token
    res.clearCookie('token');
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired' });
    }
    
    return res.status(403).json({ error: 'Invalid token' });
  }
};


// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString()
  });
});

// Google OAuth Endpoint


app.post('/user/auth/google', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token missing' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload.email_verified) {
      return res.status(403).json({ error: 'Google email not verified' });
    }

    // Check if user exists
    const [existingUser] = await pool.execute(
      "SELECT id, email, name, picture FROM users WHERE google_id = ? OR email = ?",
      [payload.sub, payload.email]
    );

    let user = existingUser[0];
    let isNewUser = false;

    // Create user if doesn't exist
    if (!user) {
      const [result] = await pool.execute(
        "INSERT INTO users (google_id, email, name, picture) VALUES (?, ?, ?, ?)",
        [payload.sub, payload.email, payload.name, payload.picture]
      );
      
      [user] = await pool.execute(
        "SELECT id, email, name, picture FROM users WHERE id = ?",
        [result.insertId]
      );
      user = user[0];
      isNewUser = true;
    }

    // Generate JWT token with 30 day expiration
    const appToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Set secure, HTTP-only cookie
//   res.cookie('token', appToken, {
//   httpOnly: true,
//   secure: process.env.NODE_ENV === 'production', // true in production
//   sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
//   maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
//   path: '/',
//   domain: process.env.COOKIE_DOMAIN // Set this in production
// });



res.cookie('token', appToken, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  maxAge: 30 * 24 * 60 * 60 * 1000,
  path: '/',
  domain: process.env.NODE_ENV === 'production' 
    ? '.onrender.com' // Production domain
    : undefined // Development (localhost)
});


    res.json({ 
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture
    }
  });
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Token verification endpoint
app.get('/user/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Logout endpoint
app.post('/user/auth/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/'
  });
  res.status(200).json({ message: 'Logged out successfully' });
});

// Routes
app.use("/user", authenticateToken, userRouter);

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});