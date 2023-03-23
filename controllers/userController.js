const bcrypt = require("bcrypt");
const User = require("../model/user");
var passport = require("passport");
var authenticate = require("../config/auth");
class userController {
  index(req, res, next) {
    res.render("register");
  }
  listUsers(req, res, next) {
    User.find({})
      .then((users) => {
        res.render("accounts", {
          title: "The list of Users",
          users: users,
          isLogin: req.session.passport === undefined ? false : true,
        });
      })
      .catch(next);
  }

  regist(req, res, next) {
    const { username, password } = req.body;
    let errors = [];
    if (!username || !password) {
      errors.push({ msg: "Please enter all fields" });
    }
    if (password.length < 6) {
      errors.push({ msg: "Password must be at least 6 characters" });
    }
    if (errors.length > 0) {
      res.render("register", {
        errors,
        username,
        password,
      });
    } else {
      User.findOne({ username: username }).then((user) => {
        if (user) {
          errors.push({ msg: "Username already exists" });
          res.render("register", {
            errors,
            username,
            password,
          });
        } else {
          const newUser = new User({
            username,
            password,
          });
          //Hash password
          bcrypt.hash(newUser.password, 10, function (err, hash) {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then((user) => {
                res.redirect("/users/login");
              })
              .catch(next);
          });
        }
      });
    }
  }

  login(req, res, next) {
    res.render("login");
  }
  signin(req, res, next) {
    passport.authenticate("local", {
      successRedirect: "/users/dashboard",
      failureRedirect: "/users/login/",
      failureFlash: true,
    })(req, res, next);
  }

  changePassword(req, res, next) {
    res.render("changePassword");
  }

  submitPassword = async (req, res, next) => {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return res.render("changePassword", {
        error: "Please enter all fields!",
        currentPassword,
        newPassword,
        confirmNewPassword,
      });
    } else {
      if (
        currentPassword.length < 6 ||
        newPassword.length < 6 ||
        confirmNewPassword.length < 6
      ) {
        return res.render("changePassword", {
          error: "Password must be at least 6 characters",
          currentPassword,
          newPassword,
          confirmNewPassword,
        });
      }
      if (newPassword !== confirmNewPassword) {
        return res.render("changePassword", {
          error: "New password and confirm password do not match",
          currentPassword,
          newPassword,
          confirmNewPassword,
        });
      }
    }

    try {
      // Tìm kiếm user dựa trên ID được đính kèm trong request
      const user = await User.findById(req.user.id);

      // Xác thực mật khẩu hiện tại
      bcrypt.compare(currentPassword, user.password, (err, isMatch) => {
        if (err) {
          return res.render("changePassword", {
            error: "An error occurred, please try again later",
          });
        }
        if (isMatch) {
          bcrypt.hash(newPassword, 10, function (err, hash) {
            if (err) {
              return res.render("changePassword", {
                error: "An error occurred, please try again later",
              });
            }
            if (newPassword === currentPassword) {
              return res.render("changePassword", {
                error: "Your new password matches your old password!",
              });
            } else {
              User.updateOne({ _id: req.user.id }, { password: hash })
                .then(() => {
                  res.redirect("/users/login");
                })
                .catch((err) => {
                  console.log(err);
                  return res.render("changePassword", {
                    error: "An error occurred, please try again later",
                  });
                });
            }
          });
        } else {
          return res.render("changePassword", {
            error: "Current password is incorrect",
            currentPassword,
            newPassword,
            confirmNewPassword,
          });
        }
      });
    } catch (err) {
      console.log(err);
      return res.render("changePassword", {
        error: "An error occurred, please try again later",
      });
    }
  };

  dashboard(req, res, next) {
    console.log("dashboard: ", req.user);
    res.redirect("/players");
  }
  signout(req, res, next) {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      req.flash("success_msg", "You are logged out");
      //  res.clearCookie('jwt');
      res.redirect("/users/login");
    });
  }

  //update user
  formEdit(req, res, next) {
    const userId = req.session.passport.user.id;
    console.log(userId);
    User.findById(userId)
      .then((user) => {
        console.log(user);
        res.render("profile", {
          title: "The detail of User",
          user: user,
          isLogin: req.session.passport === undefined ? false : true,
        });
      })
      .catch((err) => {
        console.log(err);
      });
  }
  edit(req, res, next) {
    var data = {
      name: req.body.name,
      YOB: req.body.yob,
    };
    User.updateOne({ _id: req.session.passport.user.id }, data)
      .then(() => {
        req.flash("success_msg", "Updated successfully!");
        res.redirect(`/users/edit`);
      })
      .catch((err) => {
        req.flash("error_msg", err);
        res.redirect(`/users/edit`);
      });
  }
}

// app.post('/login', (req, res, next) => {
//     passport.authenticate('local', { session: false }, (err, user, info) => {
//         if (err) {
//             return next(err);
//         }
//         if (!user) {
//             req.flash('error', 'Invalid username or password');
//             return res.redirect('/login');
//         }
//         const token = jwt.sign({ username: user.username }, 'your_secret_key');
//         res.cookie('jwt', token, { httpOnly: true });
//         res.redirect('/protected');
//     })(req, res, next);
// });
// app.get('/protected', jwtAuth, (req, res) => {
//   res.render('protected', { user: req.user });
// });
// app.get('/logout', (req, res) => {
//   res.clearCookie('jwt');
//   req.logout();
//   res.redirect('/');
// });

// file ejs
// <script>
//     const token = '<%= req.cookies.jwt %>';
//     const headers = new Headers();
//     headers.append('Authorization', `Bearer ${token}`);
//     fetch('/api/data', { headers })
//         .then(response => response.json())
//         .then(data => console.log(data))
//         .catch(error => console.error(error));
// </script>
module.exports = new userController();
