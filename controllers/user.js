const axios = require("axios");
const pool = require("../db");
const jwt = require("jsonwebtoken");

const JIKAN_BASE_URL = process.env.JIKAN_BASE_URL || "https://api.jikan.moe/v4";
const CACHE_EXPIRY = 15 * 60 * 1000; // 15 minutes
const cache = {};

// Rate limiting middleware
const jikanPerSecondLimiter = (req, res, next) => {
  const now = Date.now();
  const windowStart = now - 1000;

  const recentRequests = Object.values(
    req.app.locals.jikanRequests || {}
  ).filter((timestamp) => timestamp >= windowStart);

  if (recentRequests.length >= 3) {
    return res.status(429).json({
      error: "Too many requests to Jikan API. Please slow down.",
      retryAfter: 1,
    });
  }

  if (!req.app.locals.jikanRequests) {
    req.app.locals.jikanRequests = {};
  }
  req.app.locals.jikanRequests[now] = now;

  Object.keys(req.app.locals.jikanRequests).forEach((timestamp) => {
    if (timestamp < now - 5000) {
      delete req.app.locals.jikanRequests[timestamp];
    }
  });

  next();
};

// Updated authenticate middleware
const authenticate = async (req, res, next) => {
  const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Verify user exists in database
    const [user] = await pool.execute(
      "SELECT id, email, name, picture FROM users WHERE id = ?",
      [decoded.userId]
    );

    if (!user[0]) {
      return res.status(403).json({ error: "User not found" });
    }

    req.user = user[0];
    next();
  } catch (err) {
    console.error("Token verification error:", err);

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Session expired" });
    }

    return res.status(403).json({ error: "Invalid token" });
  }
};

// Anime endpoints

const animeSearch = async (req, res) => {
  try {
    const { query, year, page = 1, sort } = req.query;
    const cacheKey = `${query}-${year}-${page}-${sort}`;

    if (
      cache[cacheKey] &&
      Date.now() - cache[cacheKey].timestamp < CACHE_EXPIRY
    ) {
      return res.json(cache[cacheKey].data);
    }

    let url = `${JIKAN_BASE_URL}/anime?page=${page}`;

    if (query) {
      url += `&q=${encodeURIComponent(query)}`;
      // For alphabetical sorting when searching by single character
      if (query.length === 1 && sort === "asc") {
        url += `&order_by=title&sort=asc`;
      }
    }

    if (year) url += `&start_date=${year}-01-01&end_date=${year}-12-31`;

    const response = await axios.get(url, {
      timeout: 5000,
      headers: {
        "X-Request-Timestamp": Date.now(),
      },
    });

    cache[cacheKey] = {
      data: response.data,
      timestamp: Date.now(),
    };

    res.json(response.data);
  } catch (error) {
    console.error("Jikan API error:", error.message);
    const status = error.response?.status || 500;
    res.status(status).json({
      error: status === 504 ? "Request timeout" : "Failed to fetch anime data",
    });
  }
};

const fetchAllAnime = async (req, res) => {
  try {
    const { sort, year, page = 1 } = req.query;
    const cacheKey = `all-anime-${sort || "default"}${
      year ? `-${year}` : ""
    }-page-${page}`;

    if (
      cache[cacheKey] &&
      Date.now() - cache[cacheKey].timestamp < CACHE_EXPIRY
    ) {
      return res.json(cache[cacheKey].data);
    }

    let url = `${JIKAN_BASE_URL}/anime?page=${page}`;

    if (sort === "top") {
      url += "&order_by=score&sort=desc";
    } else if (sort === "popular") {
      url += "&order_by=members&sort=desc";
    }

    if (year) {
      url += `&start_date=${year}-01-01&end_date=${year}-12-31`;
    }

    const response = await axios.get(url, {
      timeout: 5000,
      headers: {
        "X-Request-Timestamp": Date.now(),
      },
    });

    cache[cacheKey] = {
      data: response.data,
      timestamp: Date.now(),
    };

    res.json(response.data);
  } catch (error) {
    console.error("Jikan API fetchAllAnime error:", error.message);
    const status = error.response?.status || 500;
    res.status(status).json({
      error: status === 504 ? "Request timeout" : "Failed to fetch anime",
    });
  }
};

const animeDetails = async (req, res) => {
  try {
    const { id } = req.params;
    const cacheKey = `anime-${id}`;

    if (
      cache[cacheKey] &&
      Date.now() - cache[cacheKey].timestamp < CACHE_EXPIRY
    ) {
      return res.json(cache[cacheKey].data);
    }

    const response = await axios.get(`${JIKAN_BASE_URL}/anime/${id}/full`, {
      timeout: 5000,
      headers: {
        "X-Request-Timestamp": Date.now(),
      },
    });

    cache[cacheKey] = {
      data: response.data,
      timestamp: Date.now(),
    };

    res.json(response.data);
  } catch (error) {
    console.error("Jikan API error:", error.message);
    const status = error.response?.status || 500;
    res.status(status).json({
      error:
        status === 504 ? "Request timeout" : "Failed to fetch anime details",
    });
  }
};

// Favorites endpoints

const addFavorite = async (req, res) => {
  try {
    const { userId, animeId, animeData } = req.body;

    // Verify the requesting user matches the token
    if (req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Check if already favorited
    const [existing] = await pool.execute(
      "SELECT id FROM favorites WHERE user_id = ? AND anime_id = ?",
      [userId, animeId]
    );

    if (existing.length > 0) {
      return res.status(200).json({
        success: true,
        message: "Anime already in favorites",
        animeId: animeId,
      });
    }

    // Store essential anime data
    const animeDataToStore = {
      mal_id: animeId,
      title: animeData.title,
      images: animeData.images,
      score: animeData.score,
      year: animeData.year || animeData.aired?.prop?.from?.year || null,
      status: animeData.status,
      synopsis: animeData.synopsis,
      type: animeData.type,
      episodes: animeData.episodes,
      rating: animeData.rating,
      duration: animeData.duration,
      genres: animeData.genres,
      studios: animeData.studios,
      trailer: animeData.trailer,
      members: animeData.members,
    };

    await pool.execute(
      "INSERT INTO favorites (user_id, anime_id, anime_data) VALUES (?, ?, ?)",
      [userId, animeId, JSON.stringify(animeDataToStore)]
    );

    res.status(201).json({
      success: true,
      animeId: animeId,
    });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({
      error: "Failed to add favorite",
      details: error.message,
    });
  }
};

const getFavorites = async (req, res) => {
  try {
    const { userId } = req.params;

    // Verify the requesting user matches the token
    if (req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const [rows] = await pool.execute(
      "SELECT anime_id, anime_data FROM favorites WHERE user_id = ? order by created_at DESC",
      [userId]
    );

    const favorites = rows.map((row) => {
      const data = JSON.parse(row.anime_data);
      return {
        ...data,
        mal_id: row.anime_id,
        id: row.anime_id, // for backward compatibility
      };
    });

    res.json(favorites);
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({
      error: "Failed to fetch favorites",
      details: error.message,
    });
  }
};

const deleteFavorite = async (req, res) => {
  try {
    const { userId, animeId } = req.params;

    // Verify the requesting user matches the token
    if (req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const [result] = await pool.execute(
      "DELETE FROM favorites WHERE user_id = ? AND anime_id = ?",
      [userId, animeId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        error: "Favorite not found",
      });
    }

    res.json({
      success: true,
      animeId: animeId,
    });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({
      error: "Failed to remove favorite",
      details: error.message,
    });
  }
};

module.exports = {
  animeSearch,
  fetchAllAnime,
  animeDetails,
  addFavorite,
  getFavorites,
  deleteFavorite,
  authenticate,
  jikanPerSecondLimiter,
};
