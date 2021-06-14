require('dotenv').config() // require this as early as possible
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const bcrypt = require("bcrypt");
// const saltRounds = 12;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({extended: true}));

// set up the session
app.use(session({
    secret: "This is our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session()); // use passport to manage the session

mongoose.connect("mongodb://localhost:27017/userDB", { useUnifiedTopology: true , useNewUrlParser: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secrets: Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// will encrypt when you save a document and decrypt when you find a document
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']}) // must do this before create User model

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// this can work with any type of authentication/strategy
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID_GOOGLE,
    clientSecret: process.env.CLIENT_SECRET_GOOGLE,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {    
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FACEBOOK,
    clientSecret: process.env.CLIENT_SECRET_FACEBOOK,
    callbackURL: "http://localhost:3000/auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ['profile'] }));

app.get("/auth/google/secrets", 
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });

app.get("/auth/facebook",
    passport.authenticate('facebook', {scope: ['public_profile']}));

app.get("/auth/facebook/callback",
    passport.authenticate('facebook', {failureRedirect: "/login"}),
    function(req, res) {
        res.redirect("/secrets");
    });

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({ "secrets": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});

app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/register", function(req, res) {
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //         username: req.body.username,
    //         password: hash
    //     });
    //     newUser.save(function(err) {
    //         if (err) {
    //             console.log(err);
    //         } else {
    //             res.render("secrets"); // only render the secrets page when the client has registered
    //         }
    //     });
    // });
    
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() { // this callback is only trigger when the authentication was successful -> managed to set up cookies that saves their current log-in session
                res.redirect("/secrets");
            })
        }
    });
});

app.post("/login", function(req, res) {
    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({username: username}, function(err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if (foundUser) {
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 if (result === true) {
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });

    // const user = new User({
    //     username: req.body.username,
    //     password: req.body.password
    // });

    // req.login(user, function(err) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         passport.authenticate("local")(req, res, function() {
    //             res.redirect("/secrets");
    //         })
    //     }
    // });

    res.redirect("/secrets");
});

app.post("/secrets", function(req, res) {
    res.render("submit");
});

app.post("/submit", function(req, res) {
    if(req.isAuthenticated()){
        User.findById(req.user.id,function (err, user){
          user.secrets.push(req.body.secret);
          user.save(function (){
            res.redirect("/secrets");
          });
        });
     
      }else {
       res.redirect("/login");
      }
});
app.listen(3000, function(req, res) {
    console.log("Server running at port 3000");
});

// ### TODO: sửa lỗi cứ mỗi lần đăng nhập lại bị tạo 1 document mới trong DB