const express = require("express");
const bodyParser = require("body-parser");
const userController = require("../controllers/userController");
const userRouter = express.Router();
const { ensureAuthenticated } = require("../config/auth");
const { redirectLogin } = require("../config/redirectLogin");

userRouter.use(bodyParser.json());
userRouter.route("/").get(userController.index).post(userController.regist);
userRouter
  .route("/login")
  .get(userController.login)
  .post(userController.signin);
userRouter.route("/logout").get(userController.signout);
userRouter
  .route("/change-password")
  .get(userController.changePassword)
  .post(userController.submitPassword);
userRouter
  .route("/dashboard")
  .get(ensureAuthenticated, redirectLogin, userController.dashboard);
userRouter
  .route("/edit")
  .get(ensureAuthenticated, userController.formEdit)
  .post(ensureAuthenticated, userController.edit);
module.exports = userRouter;
