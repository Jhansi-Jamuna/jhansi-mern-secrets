require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const User = require("./models/userSchema");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "VPnuEL6WpHZv9nuGrize", // replace with process.env.SESSION_SECRET in production
    resave: false,
    saveUninitialized: false,
  })
);

// MongoDB Connection
mongoose
  .connect("mongodb+srv://jamunapawar12:jhansi2313@secondsdb.nfyn5ad.mongodb.net/userDB?retryWrites=true&w=majority&appName=secondsdb", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// Validation Regex
const emailRegex = /^\S+@\S+\.\S+$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;

// Middleware for protected routes
const requireLogin = (req, res, next) => {
  if (!req.session.userId) return res.redirect("/login");
  next();
};

// ===== ROUTES =====

// Home route
app.get('/home', (req, res) => {
  res.render('home');  // this assumes you have views/home.ejs
});

// Register GET
app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

// Register POST
app.post("/register", async (req, res) => {
  const { username: email, password } = req.body;

  console.log("Submitted Email:", email);
  console.log("Submitted Password:", password);

  if (!emailRegex.test(email)) {
    return res.render("register", {
      error: "Invalid email format",
    });
  }

  if (!passwordRegex.test(password)) {
    return res.render("register", {
      error:
        "Password must contain uppercase, lowercase, number, and be at least 6 characters long",
    });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render("register", {
        error: "Email already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name: "", // optional or remove if not required
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.redirect("/login");
  } catch (err) {
    console.error("Registration error:", err.message);
    res.render("register", {
      error: "Registration failed. Try again.",
    });
  }
});


// Login GET
app.get("/login", (req, res) => {
  res.render("login", { error: null, formData: { email: "" } });
});


// Login POST
app.post("/login", async (req, res) => {
  const { username: email, password } = req.body;

  if (!emailRegex.test(email)) {
    return res.render("login", {
      error: "Invalid email format",
      formData: { email },
    });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", {
        error: "User not found",
        formData: { email },
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("login", {
        error: "Incorrect password",
        formData: { email },
      });
    }

    req.session.userId = user._id;
    res.redirect("/secrets");
  } catch (err) {
    console.error(err);
    res.render("login", {
      error: "Invalid email or password, try again",
      formData: { email },
    });
  }
});


// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// Secrets Page (protected)
app.get("/secrets", requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.render("secrets", { user });
});

// Submit Secret
app.get("/submit", requireLogin, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.render("submit", { user });
});

app.post("/submit", requireLogin, async (req, res) => {
  const { secret } = req.body;
  try {
    await User.findByIdAndUpdate(req.session.userId, { secret });
    res.redirect("/secrets");
  } catch (err) {
    console.error(err);
    res.send("Error submitting secret");
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
