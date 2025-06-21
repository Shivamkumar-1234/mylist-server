const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");
const userController = require("../controllers/user");

// Rate limiters
const jikanRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 55,
  message: { error: "Too many requests to Jikan API. Please try again later." },
  headers: true,
});

// Anime routes
router.get(
  "/anime/search",
  jikanRateLimiter,
  userController.jikanPerSecondLimiter,
  userController.animeSearch
);

router.get(
  "/all-anime",
  jikanRateLimiter,
  userController.jikanPerSecondLimiter,
  userController.fetchAllAnime
);

router.get(
  "/anime/:id",
  jikanRateLimiter,
  userController.jikanPerSecondLimiter,
  userController.animeDetails
);

// Favorites routes
router.post(
  "/favorites",
  userController.authenticate,
  userController.addFavorite
);

router.get(
  "/favorites/:userId",
  userController.authenticate,
  userController.getFavorites
);

router.delete(
  "/favorites/:userId/:animeId",
  userController.authenticate,
  userController.deleteFavorite
);

module.exports = router;