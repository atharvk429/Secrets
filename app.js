//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const findOrCreatePlugin = require("mongoose-findorcreate");
const crypto = require("crypto");
const MongoStore = require("connect-mongo");

const app = express();
const algorithm = 'aes-256-cbc';
const key = process.env.SECRET;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URL,
      collectionName: "sessions",
      ttl: 60 * 60
    })
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => {
    console.log("Connected to MongoDB Atlas");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB Atlas: ", err);
  });

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  iv: String,
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://whispervault-ahv9.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      scope: ["profile", "email"],
    },
    async function (accessToken, refreshToken, profile, email, cb) {
      try {
        const googleId = email.id;
        const username = email.emails[0].value;

        const existingUser = await User.findOne({ username: username });

        if (existingUser) {
          if (!existingUser.googleId) {
            existingUser.googleId = googleId;
            await existingUser.save();
          }
          return cb(null, existingUser);
        } else {
          const newUser = new User({
            username: username,
            googleId: googleId,
          });
          await newUser.save();
          return cb(null, newUser);
        }
      } catch (err) {
        console.error("Error in Google OAuth strategy:", err);
        return cb(err, null);
      }
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } })
    .then(function (foundUsers) {
      const usersWithDecryptedSecrets = foundUsers.map(user => {
        if (!user.iv || !user.secret) {
          console.error("IV or secret missing for user: ", user.username);
          return user.toObject();
        }
        try {
          const originaliv = Buffer.from(user.iv, 'base64');
          const decipher = crypto.createDecipheriv(algorithm, key, originaliv);
          let originalSecret = decipher.update(user.secret, "hex", "utf-8");
          originalSecret += decipher.final("utf8");

          return {
            ...user.toObject(),
            secret: originalSecret
          };
        } catch (error) {
          console.error("Error decrypting secret for user:", user.username, error);
          return user.toObject();
        }
      });
      res.render("secrets", { usersWithSecrets: usersWithDecryptedSecrets });
    })
    .catch(function (err) {
      console.log(err);
    });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedSecret = cipher.update(submittedSecret, 'utf8', 'hex');
  encryptedSecret += cipher.final('hex');
  const base64Data = iv.toString('base64');

  User.findOne({ username: req.user.username })
    .then(function (foundUser) {
      if (foundUser) {
        foundUser.iv=base64Data;
        foundUser.secret = encryptedSecret;
        foundUser.save();
        res.redirect("/secrets");
      }
    })
    .catch(function (err) {
      console.log(err);
    });
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/register", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
    console.log("Username or password is missing");
    return res.redirect("/register");
  }

  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
    console.log("Username or password is missing");
    return res.redirect("/login");
  }

  User.findOne({ username: username })
    .then(function (foundUser) {
      if (!foundUser) {
        return res.redirect("/register");
      }

      if (!foundUser.password) {
        foundUser.setPassword(password, function (err) {
          if (err) {
            console.log(err);
            return res.redirect("/login");
          }
          foundUser.save();
          req.login(foundUser, function (err) {
            if (err) {
              console.log(err);
            }
            passport.authenticate("local")(req, res, function () {
              res.redirect("/secrets");
            });
          });
        });
      } else {
        req.login(foundUser, function (err) {
          if (err) {
            console.log(err);
          }
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        });
      }
    })
    .catch(function (err) {
      console.log(err);
      return res.redirect("/login");
    });
});

// app.listen(3000, function(){
//     console.log("Server started on port 3000.");
// });

const PORT = process.env.PORT || 3000;
// const server = app.listen(PORT, '0.0.0.0', function() {
//     console.log(`Server started on port ${PORT}.`);
// });

app.listen(PORT, "0.0.0.0", function () {
  console.log(`Server started on port ${PORT}.`);
});

// server.keepAliveTimeout = 120000;
// server.headersTimeout = 120000;
