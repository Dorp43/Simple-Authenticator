//jshint esversion:6

require('dotenv').config();
const express = require("express");
const colors = require('colors');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const _ = require("lodash");
const md5 = require("md5"); //Level 2 Hashing passwords
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", function(){
    console.log("Connected to to ".green + "userDB ".yellow + "database.".green);
});

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("Users", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({username: profile.displayName, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({username: profile.displayName, facebookId: profile.id} , function(err, user) {
      if (err) { 
          return done(err); 
        }
      done(null, user);
    });
  }
));


app.get("/", function(req,res){
    if(req.isAuthenticated()){      //Checks if user is logged in
        res.redirect("/secrets");
    }else{
        res.render("home");
    }
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    console.log(req.user.username.yellow + " has authenticated throught Google.".green);
    res.redirect("/secrets");
  });

app.get("/auth/facebook",
passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
passport.authenticate("facebook", { failureRedirect: "/login"}),
function(req, res){
    console.log(req.user.username.yellow + " has authenticated throught Facebook.".green);
    res.redirect("/secrets");
})

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err){
            console.log(err);
        } else {
            if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
    }else{
        res.redirect("/login");
    }
});

app.get("/logout", function(req,res){
    if(req.isAuthenticated()){
    console.log(req.user.username.yellow + " has logged out.".green);
    req.logout();
    res.redirect("/");
    }else{
        res.redirect("/");
    }
});

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){      //Checks if user is logged in
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register", function(req,res){
    if(req.body.password === req.body.confirmPass){
        User.register({username: req.body.username.toLowerCase(), email: req.body.email.toLowerCase()} , req.body.password, function(err, user){
            if(err){
                console.log(err);
                res.redirect("/register");
            }else{
                passport.authenticate("local")(req, res, function(){    //Registers a new user
                    console.log(req.body.username.yellow + " has registered.".green);
                    res.redirect("/secrets");   
                });
            }
        });
    }else{
        console.log("Please confirm your password.");
    }
});
   

app.post("/login", function(req,res){

    const user = new User({
        username: req.body.username.toLowerCase(),
        password: req.body.password
    });



    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                console.log(user.username.yellow + " has logged in.".green);
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(3000, function(){
    console.log("Server started on port ".green + "3000".yellow);
});