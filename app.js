//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const findOrCreate = require('mongoose-findorcreate');



const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "this secret belongs to me..",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGODB_CONNECTION);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    twitterId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model('User',userSchema);


// use static serialize and deserialize of model for passport session support
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


//google Oauth login method
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://discoversecrets.herokuapp.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Oauth using Facebook
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: "https://discoversecrets.herokuapp.com/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

// Oauth using Twitter
passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_API_KEY,
  consumerSecret: process.env.TWITTER_API_SECRET_KEY,
  callbackURL: "https://discoversecrets.herokuapp.com/auth/google/secrets"
},
function(token, tokenSecret, profile, cb) {
  User.findOrCreate({ twitterId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));



app.get('/', function (req, res) {  
    res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));
  
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect('/secrets');
  });

//authenticating using facebook
app.get('/auth/facebook',
  passport.authenticate('facebook'));

  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect('/secrets');
  });


app.get('/auth/twitter',
  passport.authenticate('twitter'));

  app.get('/auth/twitter/secrets', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });



app.get('/login', function (req, res) {  
    res.render('login');
});
app.get('/register', function (req, res) {  
    res.render('register');
});

app.get('/secrets', function (req, res) {  
    User.find({"secret": {$ne:null}}, function (err, foundUsers) { 
      if(err){
        console.log(err);
      }else {
        res.render("secrets", {usersWithSecret: foundUsers});

      }
     });
});


app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});

// Submiting users new secrets on database


app.get('/submit', function (req, res) { 
      if (req.isAuthenticated()){
        res.render('submit');
    } else {
        res.redirect('/login');
    }
 });

 app.post('/submit', function (req, res) {
   const userSecret = req.body.secret;

   console.log(req.user);
   User.findById(req.user.id, function (err, foundOne) { 
     if (err){
       console.log(err);
     } else {
       if (foundOne){
         foundOne.secret = userSecret;
         foundOne.save(function (err) { 
           res.redirect('/secrets');
          });
       }
     }
    });
   });

app.post('/register', function (req, res) {
    User.register({username: req.body.username}, req.body.password, function (err, user) {  
        if (err){
            console.log(err);
            res.redirect('/register');
        }else {
            passport.authenticate('local')(req,res, function(){
                res.redirect("/secrets");
            });
        }
    });
  });

  app.post("/login", function (req, res) {  

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {  
        if (err){
            console.log(err);
            res.redirect('/login');
        } else{
            passport.authenticate('local')(req, res, function(){
                res.redirect('/secrets');
            });
        }
    });
     
  });


let port = process.env.PORT;
  if (port == null || port == "") {
    port = 3000;
  }
  

app.listen(port, function(){
    console.log("Server is Running successfully.");
})
