const express = require("express");
const path = require("path");
require('dotenv').config();
const bcrypt = require('bcryptjs')
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb = process.env.MONGO_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;

db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);
console.log(User)

const app = express();
app.set('views', __dirname + '/views')
app.set("view engine", "ejs");

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));

//function to setting up local strategy
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, currentUser) => {
      if (err) {
        return done(err);
      }
      if (!currentUser) {
        return done(null, false, { message: "Incorrect username" });
      }
      bcrypt.compare(password, currentUser.password, (err, result) => {
        if (result) {
          return done(null, currentUser);
        } else {
          return done(null, false, { message: "Incorrect password" });
        }
      });
      // return done(null, user);
    });
  })
);
//To make sure our user is logged in, and to allow them to stay logged in as they move around our app, passport will use some data to create a cookie which is stored in the user’s browser.

passport.serializeUser(function(currentUser, done) {
  done(null, currentUser.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, currentUser) {
    done(err, currentUser);
  });
});


app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

//If you insert this code somewhere between where you instantiate the passport middleware and before you render your views, 
//you will have access to the currentUser variable in all of your views, and you won’t have to manually pass it
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => {
  let messages = [];
  if (req.session.messages) {
    messages = req.session.messages;
    req.session.messages = [];
  }
  res.render("index", { messages });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({ username: req.body.username, password: hashedPassword });
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});
//adding login route
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureMessage: true
  })
)
app.get("/log-out", (req, res) => {
  req.session.destroy(function (err) {
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));