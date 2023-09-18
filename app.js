require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();
const port = 3000;

app.use(express.static(__dirname + "/public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "theSecretIsThatThereIsNoSecretToLookForAnyWay.",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  passwordHash: String,
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));
app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout( (err) => {
      if (err) {
          console.log(err);
      } else {
          res.redirect("/");
      }
  });
});

app.post("/register", async (req, res) => {
  try {
    const user = await User.register(
      { username: req.body.username },
      req.body.password
    );

    req.login(user, async (err) => {
      if (err) {
        console.error(err);
        return res.redirect("/register");
      }
      await passport.authenticate("local")(req, res, () => {
        return res.redirect("/secrets");
      });
    });
  } catch (err) {
    console.error(err);
    res.redirect("/register");
  }
});

app.post("/login", async (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, async (err) => {
    if (err) {
      console.error(err);
      return res.redirect("/login");
    }
    await passport.authenticate("local")(req, res, () => {
      return res.redirect("/secrets");
    });
  });
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
