require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const md5 = require('md5');

const app = express();
const port = process.env.PORT;

app.use(express.static(__dirname + "/public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = new mongoose.model("User", userSchema);

app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));
app.get("/secrets", (req, res) => res.render("secrets"));
app.get("/logout", (req, res) => res.redirect("/"));

app.post("/register", async (req, res) => {
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password)
  });

  try {
    await newUser.save();
    res.redirect("secrets");
  } catch(error) {
    console.error("Error during user save:", error);
  }

});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = md5(req.body.password);
  
  try {
    const foundUser = await User.findOne({email: username});
    if (!foundUser) {
      return res.status(404).send('User not found');
    }
  
    if (foundUser.password === password) {
      return res.render('secrets');
    } else {
      return res.status(401).send('Incorrect password');
    }
  } catch {
    console.error('Error while finding user:', error);
    return res.status(500).send('Internal Server Error');
  }
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
