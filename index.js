const express = require('express');
const session = require('express-session');
const pg = require('pg');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');
const dotenv = require('dotenv');
dotenv.config();

const app = express(); // <== Объявляем `app` ДО использования

// Подключение к PostgreSQL
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Проверка подключения
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Ошибка подключения к базе данных:', err);
  } else {
    console.log('✅ Успешное подключение к базе:', res.rows[0]);
  }
});

// Настройка сессий
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'mySecret', // Задай переменную в .env
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 1 неделя
    secure: process.env.NODE_ENV === 'production', // secure only in production
    sameSite: 'lax'
  }
}));

// Настройки представлений и парсинг тела запроса
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Пример маршрута
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Пример логина
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Подключение к базе и проверка пользователя
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password = $2', [username, password]);
    if (result.rows.length > 0) {
      req.session.user = result.rows[0];
      res.redirect('/dashboard');
    } else {
      res.status(401).send('Неверные учетные данные');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Внутренняя ошибка сервера');
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.status(403).send('Доступ запрещен');
  res.render('dashboard', { user: req.session.user });
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
