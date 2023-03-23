const express = require("express");
const nationRouter = express.Router();
const bodyParser = require("body-parser");
const nationController = require("../controllers/nationController");
const { ensureAuthenticated } = require("../config/auth");
const { requireRole } = require("../config/verifyRole");
nationRouter.use(bodyParser.json());
nationRouter
  .route("/")
  .get(ensureAuthenticated, requireRole, nationController.index)
  .post(ensureAuthenticated, requireRole, nationController.create);
nationRouter
  .route("/edit/:nationId")
  .get(ensureAuthenticated, requireRole, nationController.formEdit)
  .post(ensureAuthenticated, requireRole, nationController.edit);
nationRouter
  .route("/search")
  .get(nationController.search)
  .post(nationController.search);
nationRouter
  .route("/delete/:nationId")
  .get(ensureAuthenticated, requireRole, nationController.delete);

module.exports = nationRouter;
