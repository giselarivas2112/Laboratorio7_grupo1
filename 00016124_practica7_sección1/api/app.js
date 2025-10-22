// app.js
import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_jwt_secret"; // Cambia esto en producción

app.use(bodyParser.json());
app.use(cors());

// "Base de datos" temporal
const users = [];

// Middleware para verificar token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1]; // "Bearer TOKEN"
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// ----------------- RUTAS -----------------

// Registro de usuario
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  // Verificar si ya existe el usuario
  const existingUser = users.find(u => u.email === email);
  if (existingUser) return res.status(400).json({ message: "User already exists" });

  // Hashear la contraseña
  const hashedPassword = await bcrypt.hash(password, 10);

  // Guardar usuario
  const newUser = { id: users.length + 1, email, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: "User registered successfully", user: { id: newUser.id, email: newUser.email } });
});

// Login de usuario
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
  res.status(200).json({ token });
});

// Ruta protegida
app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ message: "Protected data accessed", user: req.user });
});

// Iniciar servidor
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
