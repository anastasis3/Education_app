// index.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


const app = express();
const port = process.env.PORT || 3000;

// Настройки подключения к базе
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Проверка подключения
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Ошибка подключения к базе:', err);
  } else {
    console.log('✅ Успешное подключение к базе:', res.rows[0]);
  }
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Статические файлы (например, HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// Регистрация
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send('Email и пароль обязательны');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING *',
      [email, hashedPassword, 'student'] // или 'teacher' по умолчанию
    );

    const user = result.rows[0];
    res.render('dashboard', { user });
  } catch (error) {
    if (error.code === '23505') {
      res.status(409).send('Такой email уже зарегистрирован');
    } else {
      console.error('Ошибка регистрации:', error);
      res.status(500).send('Внутренняя ошибка сервера');
    }
  }
});


// Вход
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send('Email и пароль обязательны');

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).send('Неверный email или пароль');
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).send('Неверный email или пароль');
    }

    res.render('dashboard', { user });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).send('Внутренняя ошибка сервера');
  }
});


// Стартовая страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

// Страница dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Запуск сервера
app.listen(port, () => {
  console.log(`🚀 Сервер запущен на порту ${port}`);
});
