var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

module.exports = {
        ensureAuthenticated: function(req, res, next) {
           if(req.isAuthenticated()){
               return next();
           }
           req.flash('error_msg', 'Please log in first!');
           res.redirect('/users/login');
        }
}
   
      //  const jwtAuth = (req, res, next) => {
      //    const token = req.cookies.jwt;
      //    if (!token) {
      //      return res.redirect('/login');
      //    }
      //    jwt.verify(token, 'your_secret_key', (err, decoded) => {
      //      if (err) {
      //        return res.redirect('/login');
      //      }
      //      req.user = decoded;
      //      next();
      //    });
      //  };  