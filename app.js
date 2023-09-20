require("dotenv").config();
const https = require("https");
const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook");
const { get } = require("http");

const app = express();
const port = 3000;

const options = {
  key: fs.readFileSync("key.pem", "utf8"),
  cert: fs.readFileSync("cert.pem", "utf8"),
};
const server = https.createServer(options, app);

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
  googleId: String,
  facebookId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "https://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => res.render("home"));

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => res.render("login"));

app.get("/register", (req, res) => res.render("register"));

app.get('/secrets', async (req, res) => {
  try {
    const foundUsers = await User.find({ secret: { $ne: null } }).exec();
    
    if (foundUsers) {
      return res.render('secrets', { usersWithSecrets: foundUsers });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).send('Internal Server Error');
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;
  const foundUser = await User.findById(req.user.id);
  if (foundUser) {
    foundUser.secret = submittedSecret;
    try {
      await foundUser.save();
      res.redirect("/secrets");
    } catch (error) {
      console.error("Error while saving user data:", error);
    }
  }
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

server.listen(port, () => {
  console.log(`HTTPS server is running on port ${port}`);
});
