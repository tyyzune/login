const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// Conectar MongoDB
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB conectado"))
  .catch(err => console.error("Erro MongoDB:", err));

// Schema de usuário
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
  avatar: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

// ROTAS

// Registro
app.post("/register", async (req, res) => {
  const { email, password, name, avatar } = req.body;

  if(!email || !password || !name) {
    return res.status(400).json({ error: "Preencha todos os campos" });
  }

  try {
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: "Email já cadastrado" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hash, name, avatar });

    res.json({ success: true, user: { id: user._id, name, avatar } });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if(!email || !password) return res.status(400).json({ error: "Preencha todos os campos" });

  try {
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ error: "Usuário não encontrado" });

    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(401).json({ error: "Senha inválida" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token, user: { id: user._id, name: user.name, avatar: user.avatar } });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Servidor rodando na porta", PORT));
