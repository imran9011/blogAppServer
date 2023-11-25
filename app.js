require("dotenv").config();
require("express-async-errors");
// express
const express = require("express");
const app = express();
app.set("trust proxy", 1);
app.use("/public", express.static(__dirname + "/public"));
const cors = require("cors");

// sanitize html
const sanitizeHtml = require("sanitize-html");

// file upload
const multer = require("multer");
const uploadMiddleware = multer({ dest: "./public/uploads/" });
// file
const fs = require("fs");

// DB
const connectDB = require("./db/connect.js");
const User = require("./models/User.js");
const Post = require("./models/Post.js");

// auth token
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

// middleware - change origin if needed
app.use(
  cors({
    credentials: true,
    origin: process.env.CLIENT_URL,
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  })
);
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET));

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.create({ username, password });
  return res.status(201).json({ user });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  const ismatch = await user.comparePassword(password);
  if (ismatch) {
    jwt.sign(
      { username, user_id: user._id },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_LIFETIME,
      },
      (err, token) => {
        if (err) return res.status(400).json({ msg: "ERROR" });
        const oneDay = 1000 * 60 * 60 * 24;
        res.cookie("token", "Bearer " + token, {
          httpOnly: true,
          expires: new Date(Date.now() + oneDay),
          secure: true,
          signed: true,
          secret: process.env.COOKIE_SECRET,
          sameSite: "none",
        });
        return res.status(200).json({ user_id: user._id, username });
      }
    );
  } else return res.status(400).json({ msg: "ERROR" });
});

app.get("/profile", async (req, res) => {
  const { token } = req.signedCookies;
  const verifyToken = token.split(" ")[1];
  jwt.verify(verifyToken, process.env.JWT_SECRET, {}, (err, info) => {
    if (err) return res.status(401).json({ msg: "credential error" });
    const user = User.findById(info.user_id);
    if (!user) {
      return res.status(401).json({ msg: "credential error" });
    }
    return res.status(200).json(info);
  });
});

app.post("/logout", (req, res) => {
  res.cookie("token", "logout", {
    httpOnly: true,
    secure: true,
    signed: true,
    secret: process.env.COOKIE_SECRET,
    sameSite: "none",
  });
  return res.status(200).json("logged-out");
});

app.delete("/post/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { token } = req.signedCookies;
    const verifyToken = token.split(" ")[1];
    const user = jwt.verify(verifyToken, process.env.JWT_SECRET);
    if (!user) return res.status(401).json("Not authorised");
    await Post.deleteOne({ _id: id });
    return res.status(200).json("ok");
  } catch (error) {
    console.log(error);
    return res.status(401).json("Not authorised");
  }
});

app.get("/post/:id", async (req, res) => {
  const { id: _id } = req.params;
  const post = await Post.findById({ _id }).populate("author", ["username"]);
  return res.status(200).json(post);
});

app.post("/post", uploadMiddleware.single("file"), async (req, res, next) => {
  const { originalname, path } = req.file;
  const parts = originalname.split(".");
  const ext = parts[parts.length - 1];
  const newPath = path + "." + ext;
  fs.renameSync(path, newPath);

  const { token } = req.signedCookies;
  const verifyToken = token.split(" ")[1];
  const user = jwt.verify(verifyToken, process.env.JWT_SECRET);
  if (!user) return res.status(401).json("Not authorised");
  const { title, summary, content } = req.body;
  const sanitizeContent = sanitizeHtml(content);
  const post = await Post.create({
    title,
    summary,
    content: sanitizeContent,
    cover: newPath,
    author: user.user_id,
  });
  return res.status(201).json(post);
});

app.put("/post", uploadMiddleware.single("file"), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split(".");
    const ext = parts[parts.length - 1];
    newPath = path + "." + ext;
    fs.renameSync(path, newPath);
  }

  try {
    const { token } = req.signedCookies;
    const verifyToken = token.split(" ")[1];
    const user = jwt.verify(verifyToken, process.env.JWT_SECRET);
    const { id, title, summary, content } = req.body;
    const postfind = await Post.findById(id);
    if (JSON.stringify(postfind.author._id) === JSON.stringify(user.user_id)) {
      postfind.title = title;
      postfind.summary = summary;
      postfind.content = content;
      postfind.cover = newPath ? newPath : postfind.cover;
      postfind.save();
      return res.status(200).json(postfind);
    } else {
      return res.status(400).json("not author");
    }
  } catch (error) {
    console.log(error);
    throw error;
  }
});

app.get("/post", async (req, res) => {
  const posts = await Post.find().populate("author", ["username"]).sort({ createdAt: -1 });
  return res.status(200).json(posts);
});

app.get("/user/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const posts = await Post.find({ author: id }).populate("author", ["username"]).sort({ createdAt: -1 });
    const userName = await User.findOne({ _id: id }).select("username");
    return res.status(200).json({ posts, userName });
  } catch (error) {
    console.log(error);
  }
});
async function start() {
  await connectDB(process.env.MONGO_URL);
  app.listen(10000, console.log("listening"));
}
start();
