require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

/* ----------------- MONGODB ----------------- */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

/* ----------------- MIDDLEWARE ----------------- */
app.use(cors({
  origin: "https://zerobugansh.github.io",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json());

/* ----------------- USER MODEL ----------------- */
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "student" },
  isPaid: { type: Boolean, default: false },
  payments: [
    {
      orderId: String,
      paymentId: String,
      amount: Number,
      paidAt: { type: Date, default: Date.now }
    }
  ]
});

const User = mongoose.model("User", userSchema);

/* ----------------- AUTH ----------------- */
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      password: hashedPassword
    });

    res.json({ message: "Registered successfully" });
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

/* ----------------- ADMIN ----------------- */
app.get("/admin", async (req, res) => {
  try {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Access denied" });

    const users = await User.find().select("-password");

    let totalRevenue = 0;
    users.forEach(u => {
      if (u.payments) {
        u.payments.forEach(p => {
          totalRevenue += p.amount;
        });
      }
    });

    res.json({
      totalUsers: users.length,
      paidUsers: users.filter(u => u.isPaid).length,
      totalRevenue,
      students: users
    });

  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

/* ----------------- RAZORPAY ----------------- */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

app.post("/create-order", async (req, res) => {
  try {
    const order = await razorpay.orders.create({
      amount: 100,
      currency: "INR",
      receipt: "receipt_order"
    });
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: "Order failed" });
  }
});

app.post("/verify-payment", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const token = req.headers.authorization;

    if (!token) return res.status(401).json({ error: "No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const body = razorpay_order_id + "|" + razorpay_payment_id;

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest("hex");

    if (expected !== razorpay_signature)
      return res.status(400).json({ error: "Invalid signature" });

    await User.findByIdAndUpdate(decoded.id, {
      isPaid: true,
      $push: {
        payments: {
          orderId: razorpay_order_id,
          paymentId: razorpay_payment_id,
          amount: 100
        }
      }
    });

    res.json({ status: "success" });

  } catch (err) {
    res.status(400).json({ error: "Verification failed" });
  }
});

/* ----------------- SERVER ----------------- */
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});