var express = require("express");
var router = express.Router();
const playerController = require("../controllers/playerController");
const User = require("../controllers/userController");
const { ensureAuthenticated } = require("../config/auth");
const { requireRole } = require("../config/verifyRole");
/* GET home page. */
router.get("/", playerController.home);
router.get("/paging", playerController.pagingHome);
router.get("/paging-player", playerController.paging);
router.get("/accounts", ensureAuthenticated, requireRole, User.listUsers);
module.exports = router;
