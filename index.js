
// const express = require("express");
// const cors = require("cors");
// const dotenv = require("dotenv");
// const { OAuth2Client } = require("google-auth-library");
// const helmet = require("helmet");
// const morgan = require("morgan");
// const pool = require("./db");
// const jwt = require("jsonwebtoken");
// const cookieParser = require("cookie-parser");

// dotenv.config();

// const userRouter = require("./routers/user");
// const app = express();
// const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// // --- Middleware ---
// app.use(
//   helmet({
//     crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
//     contentSecurityPolicy: {
//       directives: {
//         defaultSrc: ["'self'"],
//         scriptSrc: ["'self'", "https://accounts.google.com"],
//         connectSrc: ["'self'", process.env.CORS_ORIGIN],
//         imgSrc: ["'self'", "data:", "https://lh3.googleusercontent.com"],
//         styleSrc: ["'self'", "'unsafe-inline'"],
//         frameSrc: ["'self'", "https://accounts.google.com"],
//       },
//     },
//   })
// );

// // --- CORS ---
// const allowedOrigins = [
//   "https://my-list-dun.vercel.app", 
//   "http://localhost:3000"
// ];

// app.use(
//   cors({
//     origin: function (origin, callback) {
//       // Allow requests with no origin (like mobile apps or curl requests)
//       if (!origin) return callback(null, true);
//       if (allowedOrigins.indexOf(origin) !== -1) {
//         callback(null, true);
//       } else {
//         callback(new Error("Not allowed by CORS"));
//       }
//     },
//     credentials: true,
//     exposedHeaders: ["set-cookie"],
//   })
// );

// // --- Parsers & Logging ---
// app.use(cookieParser());
// app.use(express.json({ limit: "10kb" }));
// app.use(morgan("dev"));

// // --- Auth Middleware ---
// const authenticateToken = async (req, res, next) => {
//   const token =
//     req.cookies?.token || req.headers["authorization"]?.split(" ")[1];

//   if (!token) {
//     return res.status(401).json({ error: "Authentication required" });
//   }

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     const [user] = await pool.execute(
//       "SELECT id, email, name, picture FROM users WHERE id = ?",
//       [decoded.userId]
//     );

//     if (!user[0]) {
//       return res.status(403).json({ error: "User not found" });
//     }

//     req.user = user[0];
//     next();
//   } catch (err) {
//     console.error("Token verification error:", err);
//     res.clearCookie("token");

//     if (err.name === "TokenExpiredError") {
//       return res.status(401).json({ error: "Session expired" });
//     }

//     return res.status(403).json({ error: "Invalid token" });
//   }
// };

// // --- Health Check ---
// app.get("/health", (req, res) => {
//   res.status(200).json({
//     status: "healthy",
//     timestamp: new Date().toISOString(),
//   });
// });

// // --- Google OAuth Login ---
// app.post("/user/auth/google", async (req, res) => {
//   const { token } = req.body;
//   if (!token) return res.status(400).json({ error: "Token missing" });

//   try {
//     const ticket = await googleClient.verifyIdToken({
//       idToken: token,
//       audience: process.env.GOOGLE_CLIENT_ID,
//     });

//     const payload = ticket.getPayload();
//     if (!payload.email_verified) {
//       return res.status(403).json({ error: "Google email not verified" });
//     }

//     const [existingUser] = await pool.execute(
//       "SELECT id, email, name, picture FROM users WHERE google_id = ? OR email = ?",
//       [payload.sub, payload.email]
//     );

//     let user = existingUser[0];

//     if (!user) {
//       const [result] = await pool.execute(
//         "INSERT INTO users (google_id, email, name, picture) VALUES (?, ?, ?, ?)",
//         [payload.sub, payload.email, payload.name, payload.picture]
//       );

//       [user] = await pool.execute(
//         "SELECT id, email, name, picture FROM users WHERE id = ?",
//         [result.insertId]
//       );

//       user = user[0];
//     }

//     const appToken = jwt.sign(
//       { userId: user.id, email: user.email },
//       process.env.JWT_SECRET,
//       { expiresIn: "30d" }
//     );

//     // Set cookie with proper domain and secure settings
//     const isProduction = process.env.NODE_ENV === "production";
//     const domain = isProduction ? ".vercel.app" : undefined;

//     res.cookie("token", appToken, {
//       httpOnly: true,
//       secure: isProduction,
//       sameSite: isProduction ? "none" : "lax",
//       maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
//       domain: domain,
//       path: "/",
//     });

//     res.json({
//       user: {
//         id: user.id,
//         email: user.email,
//         name: user.name,
//         picture: user.picture,
//       },
//     });
//   } catch (err) {
//     console.error("Google auth error:", err);
//     res.status(401).json({ error: "Authentication failed" });
//   }
// });

// // --- Verify Auth ---
// app.get("/user/auth/verify", authenticateToken, (req, res) => {
//   res.status(200).json({ user: req.user });
// });

// // --- Logout ---
// app.post("/user/auth/logout", (req, res) => {
//   const isProduction = process.env.NODE_ENV === "production";
//   const domain = isProduction ? ".vercel.app" : undefined;

//   res.clearCookie("token", {
//     httpOnly: true,
//     secure: isProduction,
//     sameSite: isProduction ? "none" : "lax",
//     path: "/",
//     domain: domain,
//   });
//   res.status(200).json({ message: "Logged out successfully" });
// });

// // --- Routes ---
// app.use("/user", authenticateToken, userRouter);

// // --- Fallbacks ---
// app.use((err, req, res, next) => {
//   console.error(err.stack);
//   res.status(500).json({ error: "Internal Server Error" });
// });

// app.use((req, res) => {
//   res.status(404).json({ error: "Not Found" });
// });

// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });



















const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const pool = require("./db");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt=require("bcrypt")

dotenv.config();

const userRouter = require("./routers/user");
const app = express();

// --- Middleware ---
app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'", process.env.CORS_ORIGIN],
        imgSrc: ["'self'", "data:"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
  })
);

// --- CORS ---
const allowedOrigins = [
  "https://my-list-dun.vercel.app", 
  "http://localhost:3000"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    exposedHeaders: ["set-cookie"],
  })
);

// --- Parsers & Logging ---
app.use(cookieParser());
app.use(express.json({ limit: "10kb" }));
app.use(morgan("dev"));

// --- Auth Middleware ---
const authenticateToken = async (req, res, next) => {
  const token = req.cookies?.token || req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const [user] = await pool.execute(
      "SELECT id, email, name FROM users WHERE id = ?",
      [decoded.userId]
    );

    if (!user[0]) {
      return res.status(403).json({ error: "User not found" });
    }

    req.user = user[0];
    next();
  } catch (err) {
    console.error("Token verification error:", err);
    res.clearCookie("token");

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Session expired" });
    }

    return res.status(403).json({ error: "Invalid token" });
  }
};

// --- Health Check ---
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

// --- Signup Endpoint ---
app.post("/user/auth/signup", async (req, res) => {
  const { email, password, name } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  // Email regex validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  // Password strength validation
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  try {
    // Check if user already exists
    const [existingUser] = await pool.execute(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({ error: "Email already in use" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const [result] = await pool.execute(
      "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
      [email, hashedPassword, name]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: result.insertId, email },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    // Set cookie
    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: "/",
    });

    res.status(201).json({
      user: {
        id: result.insertId,
        email,
        name,
      },
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Failed to create user" });
  }
});

// --- Login Endpoint ---
app.post("/user/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Find user by email
    const [users] = await pool.execute(
      "SELECT id, email, password, name FROM users WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    // Set cookie
    const isProduction = process.env.NODE_ENV === "production";
    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: "/",
    });

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Failed to login" });
  }
});

// --- Verify Auth ---
app.get("/user/auth/verify", authenticateToken, (req, res) => {
  res.status(200).json({ user: req.user });
});

// --- Logout ---
app.post("/user/auth/logout", (req, res) => {
  const isProduction = process.env.NODE_ENV === "production";
  res.clearCookie("token", {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/",
  });
  res.status(200).json({ message: "Logged out successfully" });
});

// --- Routes ---
app.use("/user", authenticateToken, userRouter);

// --- Fallbacks ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Not Found" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});