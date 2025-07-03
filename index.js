require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Подключение к базе
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Сессии
app.use(session({
  secret: process.env.SESSION_SECRET || 'secretKey',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 неделя
}));

// Шаблонизатор ejs
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// Роуты

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

app.post('/register', async (req, res) => {
  const { email, password, role } = req.body; // Добавим роль при регистрации (teacher/student)
  
  if (!email || !password || !role) {
    return res.status(400).json({ error: 'Email, пароль и роль обязательны' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
      [email, hashedPassword, role]
    );
    res.status(201).json({ message: 'Пользователь зарегистрирован', userId: result.rows[0].id });
  } catch (error) {
    if (error.code === '23505') {
      res.status(409).json({ error: 'Такой email уже зарегистрирован' });
    } else {
      console.error('Ошибка регистрации:', error);
      res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Сохраняем пользователя в сессии (не пароль!)
    req.session.user = { id: user.id, email: user.email, role: user.role };

    res.status(200).json({ message: 'Успешный вход' });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Доступ запрещён. Пожалуйста, войдите в систему.');
  }
  res.render('dashboard', { user: req.session.user });
});

// Запуск сервера
app.listen(port, () => {
  console.log(`🚀 Сервер запущен на порту ${port}`);
});


app.post('/create-form', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Unauthorized');
  }

  const { title } = req.body;
  const teacherId = req.session.user.id;

  try {
    // 1. Сохраняем шаблон формы
    const formResult = await pool.query(
      'INSERT INTO form_templates (teacher_id, title) VALUES ($1, $2) RETURNING id',
      [teacherId, title]
    );
    const formId = formResult.rows[0].id;

    // 2. Обрабатываем вопросы
    for (let i = 1; i <= 4; i++) {
      const isActive = req.body[`active_${i}`] === 'on';
      const questionText = req.body[`question_${i}`]?.trim();

      // Сохраняем только если текст вопроса не пустой
      if (questionText) {
        await pool.query(
          `INSERT INTO questions (form_id, question_text, is_active, question_order)
           VALUES ($1, $2, $3, $4)`,
          [formId, questionText, isActive, i]
        );
      }
    }

    res.send('Форма успешно создана!');
  } catch (err) {
    console.error('Ошибка при создании формы:', err);
    res.status(500).send('Ошибка сервера');
  }
});
