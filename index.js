require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'secretKey',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } 
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

app.post('/register', async (req, res) => {
  const { email, password, role } = req.body;
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

    req.session.user = { id: user.id, email: user.email, role: user.role };
    res.status(200).json({ message: 'Успешный вход' });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Панель пользователя
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Доступ запрещён. Пожалуйста, войдите в систему.');
  }
  res.render('dashboard', { user: req.session.user });
});


// Форма создания
app.get('/create-form', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Доступ запрещён. Только для учителей.');
  }

  // Получаем список студентов
  const students = await pool.query('SELECT id, email FROM users WHERE role = $1 AND is_deleted = false', ['student']);
  res.render('create-form', { students: students.rows }); // Передаем список студентов в шаблон
});


// Обработка создания формы (POST)
// Обработка создания формы (POST) - исправленная версия
app.post('/create-form', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Unauthorized');
  }

  let { title, students } = req.body;
  if (!Array.isArray(students)) {
    students = students ? [students] : [];
  }

  const teacherId = req.session.user.id;

  // Отладка - посмотрим что приходит в req.body
  console.log('Данные формы:', req.body);
  console.log('Выбранные студенты:', students);

  try {
    const formResult = await pool.query(
      'INSERT INTO form_templates (teacher_id, title) VALUES ($1, $2) RETURNING id',
      [teacherId, title]
    );
    const formId = formResult.rows[0].id;

    // Создаем вопросы
    for (let i = 1; i <= 4; i++) {
      const isActive = req.body[`active_${i}`] === 'on';
      const questionText = req.body[`question_${i}`]?.trim();
      const questionType = req.body[`question_type_${i}`];

      if (questionText) {
        const result = await pool.query(
          `INSERT INTO questions (form_id, question_text, is_active, question_type, question_order)
           VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [formId, questionText, isActive, questionType, i]
        );
        const questionId = result.rows[0].id;

        // Опции для вопросов
        if (['radio', 'checkbox', 'dropdown'].includes(questionType)) {
          let optionIndex = 1;
          while (req.body[`option_${i}_${optionIndex}`]) {
            const optionText = req.body[`option_${i}_${optionIndex}`].trim();
            if (optionText) {
              await pool.query(
                'INSERT INTO options (question_id, option_text) VALUES ($1, $2)',
                [questionId, optionText]
              );
            }
            optionIndex++;
          }
        }
      }
    }

    // Назначаем форму выбранным студентам - ИСПРАВЛЕНО
    for (const studentId of students) {
      await pool.query(
        'INSERT INTO form_assignments (form_id, user_id) VALUES ($1, $2)',
        [formId, studentId]
      );
    }

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Ошибка при создании формы:', err);
    console.error('Детали ошибки:', err.message);
    console.error('Код ошибки:', err.code);
    res.status(500).send('Ошибка сервера');
  }
});

// Маршрут для просмотра всех форм текущего учителя
app.get('/forms', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Доступ запрещён');
  }

  try {
    const teacherId = req.session.user.id;
    const result = await pool.query(
      'SELECT * FROM form_templates WHERE teacher_id = $1 ORDER BY created_at DESC',
      [teacherId]
    );

    res.render('forms', { forms: result.rows, user: req.session.user });
  } catch (err) {
    console.error('Ошибка при получении форм:', err);
    res.status(500).send('Ошибка сервера');
  }
});

//РЕДАКТИРОВАНИЕ ФОРМЫ
app.get('/edit-form/:id', async (req, res) => {
  const formId = req.params.id;
  try {
    // Получаем форму по id
    const formResult = await pool.query('SELECT * FROM form_templates WHERE id = $1', [formId]);
    const form = formResult.rows[0];

    if (!form) {
      return res.status(404).send('Форма не найдена');
    }

    // Получаем вопросы, связанные с этой формой
    const questionsResult = await pool.query('SELECT * FROM questions WHERE form_id = $1 ORDER BY question_order', [formId]);
    const questions = questionsResult.rows;

    // Передаем форму и вопросы в шаблон
    res.render('edit-form', { form: { ...form, questions } });
  } catch (err) {
    console.error('Ошибка при загрузке формы для редактирования:', err);
    res.status(500).send('Ошибка сервера');
  }
});


//ОБНОВЛЕНИЕ ФОРМЫ
app.post('/edit-form/:id', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Access denied. Teachers only.');
  }

  const formId = req.params.id;
  const userId = req.session.user.id;
  const { title } = req.body;

  try {
    const formCheck = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1 AND teacher_id = $2',
      [formId, userId]
    );

    if (formCheck.rowCount === 0) {
      return res.status(404).send('Form not found or access denied');
    }

    await pool.query(
      'UPDATE form_templates SET title = $1 WHERE id = $2',
      [title, formId]
    );

    await pool.query('DELETE FROM questions WHERE form_id = $1', [formId]);
    for (let i = 1; i <= 4; i++) {
      const isActive = req.body[`active_${i}`] === 'on';
      const questionText = req.body[`question_${i}`]?.trim();

      if (questionText) {
        await pool.query(
          `INSERT INTO questions (form_id, question_text, is_active, question_order)
           VALUES ($1, $2, $3, $4)`,
          [formId, questionText, isActive, i]
        );
      }
    }

     res.redirect('/forms');
  } catch (err) {
    console.error('Error updating form:', err);
    res.status(500).send('Server error');
  }
});

//УДАЛЕНИЕ ФОРМЫ
app.post('/delete-form/:id', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Access denied. Teachers only.');
  }

  const formId = req.params.id;
  const userId = req.session.user.id;

  try {
    const formCheck = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1 AND teacher_id = $2',
      [formId, userId]
    );

    if (formCheck.rowCount === 0) {
      return res.status(404).send('Form not found or access denied');
    }

    await pool.query('DELETE FROM questions WHERE form_id = $1', [formId]);

    await pool.query('DELETE FROM form_templates WHERE id = $1', [formId]);

    res.redirect('/forms');
  } catch (err) {
    console.error('Error deleting form:', err);
    res.status(500).send('Server error');
  }
});


//ПРОСМОТР ФОРМЫ
app.get('/view-form/:id', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Access denied');
  }

  const formId = req.params.id;
  const userId = req.session.user.id;

  try {
    const formResult = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1 AND teacher_id = $2',
      [formId, userId]
    );

    if (formResult.rowCount === 0) {
      return res.status(404).send('Form not found or access denied');
    }

    const form = formResult.rows[0];

    const questionsResult = await pool.query(
      'SELECT * FROM questions WHERE form_id = $1 ORDER BY question_order',
      [formId]
    );

    res.render('view-form', {
      user: req.session.user,
      form,
      questions: questionsResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


//РЕЗУЛЬТАТЫ
app.get('/results/:formId', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Access denied');
  }

  const formId = req.params.formId;
  const userId = req.session.user.id;

  try {
    const formResult = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1 AND teacher_id = $2',
      [formId, userId]
    );

    if (formResult.rowCount === 0) {
      return res.status(404).send('Form not found or access denied');
    }

    const form = formResult.rows[0];

    const responsesResult = await pool.query(`
      SELECT fr.id as response_id, u.id as user_id, u.email as user_name, fr.submitted_at, fr.form_id
      FROM form_responses fr
      JOIN users u ON fr.user_id = u.id
      WHERE fr.form_id = $1
      ORDER BY fr.submitted_at DESC
    `, [formId]);

    res.render('results-list', {
      user: req.session.user,
      form,
      responses: responsesResult.rows,
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

//ОЦЕНКА КОНКРЕТНОГО ОТВЕТА

app.post('/results/grade', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Access denied');
  }

  const teacherId = req.session.user.id;
  const { student_id, form_id, grade, comment } = req.body;

  try {
    const formCheck = await pool.query(
      'SELECT id FROM form_templates WHERE id = $1 AND teacher_id = $2',
      [form_id, teacherId]
    );

    if (formCheck.rowCount === 0) {
      return res.status(403).send('Access denied or form not found');
    }

    const existingGrade = await pool.query(
      'SELECT id FROM grades WHERE teacher_id = $1 AND student_id = $2 AND form_id = $3',
      [teacherId, student_id, form_id]
    );

    if (existingGrade.rowCount > 0) {
      await pool.query(
        `UPDATE grades SET grade = $1, comment = $2, graded_at = NOW() WHERE id = $3`,
        [grade, comment, existingGrade.rows[0].id]
      );
    } else {
      await pool.query(
        `INSERT INTO grades (teacher_id, student_id, form_id, grade, comment) VALUES ($1, $2, $3, $4, $5)`,
        [teacherId, student_id, form_id, grade, comment]
      );
    }

    res.redirect(`/results/view/${form_id}/${student_id}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


//ПРОСМОТР
app.get('/results/view/:formId/:studentId', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Access denied');
  }

  const teacherId = req.session.user.id;
  const { formId, studentId } = req.params;

  try {
    const formCheck = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1 AND teacher_id = $2',
      [formId, teacherId]
    );

    if (formCheck.rowCount === 0) {
      return res.status(403).send('Access denied or form not found');
    }

    const answersResult = await pool.query(
      `SELECT q.question_text, a.answer_text, a.file_url
       FROM answers a
       JOIN questions q ON a.question_id = q.id
       WHERE a.form_id = $1 AND a.student_id = $2
       ORDER BY q.question_order`,
      [formId, studentId]
    );

    const gradeResult = await pool.query(
      `SELECT grade, comment FROM grades
       WHERE teacher_id = $1 AND student_id = $2 AND form_id = $3`,
      [teacherId, studentId, formId]
    );

    res.render('results-view', {
      form: formCheck.rows[0],
      studentId,
      answers: answersResult.rows,
      grade: gradeResult.rows[0] || null,
      user: req.session.user,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Роут для выбора формы для просмотра результатов
app.get('/select-form-results', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    return res.status(403).send('Доступ запрещён');
  }

  try {
    const teacherId = req.session.user.id;
    const result = await pool.query(
      'SELECT * FROM form_templates WHERE teacher_id = $1 ORDER BY created_at DESC',
      [teacherId]
    );

    res.render('select-form-results', { forms: result.rows, user: req.session.user });
  } catch (err) {
    console.error('Ошибка при получении форм:', err);
    res.status(500).send('Ошибка сервера');
  }
});


// Запуск сервера
app.listen(port, () => {
  console.log(`🚀 Сервер запущен на порту ${port}`);
});
