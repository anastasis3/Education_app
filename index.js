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
// Fixed route handler for viewing forms
app.get('/view-form/:id', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Access denied');
  }

  const formId = req.params.id;
  const userId = req.session.user.id;

  try {
    // Get form information
    const formResult = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1',
      [formId]
    );

    if (formResult.rowCount === 0) {
      return res.status(404).send('Form not found');
    }

    const form = formResult.rows[0];

    // Check if user has access (either teacher who created it or student assigned to it)
    let hasAccess = false;
    
    if (req.session.user.role === 'teacher' && form.teacher_id === userId) {
      hasAccess = true;
    } else if (req.session.user.role === 'student') {
      // Check if student is assigned to this form
      const assignmentResult = await pool.query(
        'SELECT 1 FROM form_assignments WHERE form_id = $1 AND user_id = $2',
        [formId, userId]
      );
      hasAccess = assignmentResult.rowCount > 0;
    }

    if (!hasAccess) {
      return res.status(403).send('Access denied');
    }

    // Get questions for this form
    const questionsResult = await pool.query(
      'SELECT * FROM questions WHERE form_id = $1 AND is_active = true ORDER BY question_order',
      [formId]
    );

    // Use the simple template instead of the results template
    res.render('view-form-simple', {
      form,
      questions: questionsResult.rows,
      user: req.session.user
    });

  } catch (err) {
    console.error('Error viewing form:', err);
    res.status(500).send('Server error');
  }
});

// Alternative: If you want to keep using the same template, 
// you need to provide ALL the variables it expects:
app.get('/view-form/:id', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).send('Access denied');
  }

  const formId = req.params.id;
  const userId = req.session.user.id;

  try {
    // Get form information
    const formResult = await pool.query(
      'SELECT * FROM form_templates WHERE id = $1',
      [formId]
    );

    if (formResult.rowCount === 0) {
      return res.status(404).send('Form not found');
    }

    const form = formResult.rows[0];

    // Get questions
    const questionsResult = await pool.query(
      'SELECT * FROM questions WHERE form_id = $1 AND is_active = true ORDER BY question_order',
      [formId]
    );

    // If you want to use the same template, provide ALL required variables
    res.render('view-form', {
      form,
      studentId: userId,
      studentName: req.session.user.name || 'Unknown',
      studentEmail: req.session.user.email,
      answers: [], // Empty answers for preview
      grade: null, // No grade for preview
      assignedStudents: [], // Empty for preview
      totalQuestions: questionsResult.rows.length,
      responseCount: 0,
      averageGrade: null,
      submissionDate: null,
      user: req.session.user
    });

  } catch (err) {
    console.error('Error viewing form:', err);
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




// Add this route handler to your Express.js application
// Place it with your other route handlers

// Route to show active forms assigned to the student
app.get('/active-form', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).send('Доступ запрещён. Только для студентов.');
  }

  const studentId = req.session.user.id;

  try {
    // Get all forms assigned to this student that haven't been submitted yet
    const assignedFormsResult = await pool.query(`
      SELECT DISTINCT ft.id, ft.title, ft.created_at 
      FROM form_templates ft
      JOIN form_assignments fa ON ft.id = fa.form_id
      WHERE fa.user_id = $1 
      AND NOT EXISTS (
        SELECT 1 FROM form_responses fr 
        WHERE fr.form_id = ft.id AND fr.user_id = $1
      )
      ORDER BY ft.created_at DESC
    `, [studentId]);

    if (assignedFormsResult.rows.length === 0) {
      return res.render('active-form', { 
        forms: [], 
        user: req.session.user,
        message: 'У вас нет активных заданий для заполнения.' 
      });
    }

    // Get detailed information for each form including questions and options
    const formsWithDetails = [];
    
    for (const form of assignedFormsResult.rows) {
      // Get questions for this form
      const questionsResult = await pool.query(`
        SELECT q.id, q.question_text, q.question_type, q.question_order
        FROM questions q
        WHERE q.form_id = $1 AND q.is_active = true
        ORDER BY q.question_order
      `, [form.id]);

      // Get options for each question
      const questionsWithOptions = [];
      for (const question of questionsResult.rows) {
        const optionsResult = await pool.query(`
          SELECT option_text 
          FROM options 
          WHERE question_id = $1 
          ORDER BY id
        `, [question.id]);

        questionsWithOptions.push({
          ...question,
          options: optionsResult.rows.map(opt => opt.option_text)
        });
      }

      formsWithDetails.push({
        ...form,
        questions: questionsWithOptions
      });
    }

    res.render('active-form', { 
      forms: formsWithDetails, 
      user: req.session.user,
      message: null 
    });

  } catch (err) {
    console.error('Ошибка при получении активных форм:', err);
    res.status(500).send('Ошибка сервера');
  }
});

// Route to handle form submission
app.post('/submit-answer/:formId', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') {
    return res.status(403).send('Доступ запрещён. Только для студентов.');
  }

  const formId = req.params.formId;
  const studentId = req.session.user.id;

  try {
    // Check if student is assigned to this form
    const assignmentCheck = await pool.query(
      'SELECT 1 FROM form_assignments WHERE form_id = $1 AND user_id = $2',
      [formId, studentId]
    );

    if (assignmentCheck.rowCount === 0) {
      return res.status(403).send('Вы не назначены на эту форму.');
    }

    // Check if student has already submitted this form
    const submissionCheck = await pool.query(
      'SELECT 1 FROM form_responses WHERE form_id = $1 AND user_id = $2',
      [formId, studentId]
    );

    if (submissionCheck.rowCount > 0) {
      return res.status(400).send('Вы уже отправили ответы на эту форму.');
    }

    // Create form response record
    const responseResult = await pool.query(
      'INSERT INTO form_responses (form_id, user_id) VALUES ($1, $2) RETURNING id',
      [formId, studentId]
    );
    const responseId = responseResult.rows[0].id;

    // Get questions for this form
    const questionsResult = await pool.query(
      'SELECT id, question_order FROM questions WHERE form_id = $1 AND is_active = true ORDER BY question_order',
      [formId]
    );

    // Save answers
    for (const question of questionsResult.rows) {
      const answerKey = `answer_${question.question_order - 1}`; // Adjust for 0-based indexing
      let answerValue = req.body[answerKey];

      if (answerValue) {
        // Handle checkbox answers (arrays)
        if (Array.isArray(answerValue)) {
          answerValue = answerValue.join(', ');
        }

        await pool.query(
          'INSERT INTO answer_responses (response_id, question_id, answer_text) VALUES ($1, $2, $3)',
          [responseId, question.id, answerValue]
        );
      }
    }

    res.redirect('/dashboard?message=Форма успешно отправлена!');

  } catch (err) {
    console.error('Ошибка при отправке формы:', err);
    res.status(500).send('Ошибка сервера');
  }
});



// Добавьте эти роуты в ваш основной файл сервера (например, app.js или server.js)

const nodemailer = require('nodemailer');

// Настройка email транспорта (замените на ваши настройки)
const transporter = nodemailer.createTransport({
  service: 'gmail', // или другой сервис
  auth: {
    user: 'your-email@gmail.com',
    pass: 'your-app-password'
  }
});

// Роут для просмотра ответов студента и выставления оценки
app.get('/results/view/:formId/:studentId', async (req, res) => {
  try {
    const { formId, studentId } = req.params;
    
    // Проверяем, что пользователь - учитель
    if (!req.session.user || req.session.user.role !== 'teacher') {
      return res.redirect('/login');
    }

    // Получаем информацию о форме
    const formQuery = `
      SELECT ft.*, u.name as teacher_name 
      FROM form_templates ft 
      JOIN users u ON ft.teacher_id = u.id 
      WHERE ft.id = $1 AND ft.teacher_id = $2
    `;
    const formResult = await db.query(formQuery, [formId, req.session.user.id]);
    
    if (formResult.rows.length === 0) {
      return res.status(404).send('Form not found or access denied');
    }

    const form = formResult.rows[0];

    // Получаем информацию о студенте
    const studentQuery = `
      SELECT id, email, name 
      FROM users 
      WHERE id = $1 AND role = 'student'
    `;
    const studentResult = await db.query(studentQuery, [studentId]);
    
    if (studentResult.rows.length === 0) {
      return res.status(404).send('Student not found');
    }

    const student = studentResult.rows[0];

    // Получаем все вопросы формы с правильными ответами
    const questionsQuery = `
      SELECT id, question_text, question_type, correct_answer, options
      FROM questions 
      WHERE form_id = $1 AND is_active = true
      ORDER BY question_order
    `;
    const questionsResult = await db.query(questionsQuery, [formId]);
    const questions = questionsResult.rows;

    // Получаем ответы студента
    const answersQuery = `
      SELECT a.*, q.question_text, q.question_type, q.correct_answer, q.options
      FROM answers a
      JOIN questions q ON a.question_id = q.id
      WHERE a.student_id = $1 AND a.form_id = $2
      ORDER BY q.question_order
    `;
    const answersResult = await db.query(answersQuery, [studentId, formId]);
    const answers = answersResult.rows;

    // Получаем текущую оценку, если есть
    const gradeQuery = `
      SELECT grade, comment
      FROM grades
      WHERE student_id = $1 AND form_id = $2 AND teacher_id = $3
    `;
    const gradeResult = await db.query(gradeQuery, [studentId, formId, req.session.user.id]);
    const currentGrade = gradeResult.rows[0] || null;

    // Создаем объединенный массив вопросов с ответами
    const questionsWithAnswers = questions.map(question => {
      const studentAnswer = answers.find(a => a.question_id === question.id);
      return {
        ...question,
        student_answer: studentAnswer ? studentAnswer.answer_text : null,
        selected_options: studentAnswer ? studentAnswer.selected_options : null,
        file_url: studentAnswer ? studentAnswer.file_url : null,
        is_correct: checkAnswer(question, studentAnswer)
      };
    });

    res.render('grade_student', {
      form,
      student,
      questionsWithAnswers,
      currentGrade,
      title: `Grade ${student.name} - ${form.title}`
    });

  } catch (error) {
    console.error('Error loading grading page:', error);
    res.status(500).send('Server error');
  }
});

// Роут для сохранения оценки
app.post('/results/grade', async (req, res) => {
  try {
    const { student_id, form_id, grade, comment } = req.body;
    
    // Проверяем, что пользователь - учитель
    if (!req.session.user || req.session.user.role !== 'teacher') {
      return res.redirect('/login');
    }

    // Проверяем, что форма принадлежит учителю
    const formCheckQuery = `
      SELECT title FROM form_templates 
      WHERE id = $1 AND teacher_id = $2
    `;
    const formCheckResult = await db.query(formCheckQuery, [form_id, req.session.user.id]);
    
    if (formCheckResult.rows.length === 0) {
      return res.status(403).send('Access denied');
    }

    const formTitle = formCheckResult.rows[0].title;

    // Получаем информацию о студенте
    const studentQuery = `
      SELECT email, name FROM users WHERE id = $1
    `;
    const studentResult = await db.query(studentQuery, [student_id]);
    const student = studentResult.rows[0];

    // Сохраняем или обновляем оценку
    const upsertGradeQuery = `
      INSERT INTO grades (teacher_id, student_id, form_id, grade, comment)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (teacher_id, student_id, form_id) 
      DO UPDATE SET 
        grade = EXCLUDED.grade,
        comment = EXCLUDED.comment,
        graded_at = CURRENT_TIMESTAMP
    `;
    
    await db.query(upsertGradeQuery, [
      req.session.user.id,
      student_id,
      form_id,
      grade,
      comment || null
    ]);

    // Отправляем уведомление на почту студенту
    try {
      await sendGradeNotification(student.email, student.name, formTitle, grade, comment);
    } catch (emailError) {
      console.error('Error sending email:', emailError);
      // Продолжаем выполнение, даже если email не отправился
    }

    res.redirect('/results');

  } catch (error) {
    console.error('Error saving grade:', error);
    res.status(500).send('Server error');
  }
});

// Функция для проверки правильности ответа
function checkAnswer(question, studentAnswer) {
  if (!question.correct_answer || !studentAnswer) {
    return null; // Нет правильного ответа или студент не ответил
  }

  switch (question.question_type) {
    case 'radio':
    case 'dropdown':
      return studentAnswer.answer_text === question.correct_answer;
    
    case 'checkbox':
      if (!studentAnswer.selected_options) return false;
      const correctOptions = question.correct_answer.split(',').map(s => s.trim());
      const studentOptions = studentAnswer.selected_options;
      
      return correctOptions.length === studentOptions.length &&
             correctOptions.every(option => studentOptions.includes(option));
    
    case 'short_text':
      // Простая проверка на точное совпадение (можно улучшить)
      return studentAnswer.answer_text.toLowerCase().trim() === 
             question.correct_answer.toLowerCase().trim();
    
    case 'file_upload':
      return null; // Файлы нужно проверять вручную
    
    default:
      return null;
  }
}

// Функция для отправки уведомления об оценке
async function sendGradeNotification(studentEmail, studentName, formTitle, grade, comment) {
  const subject = `Оценка за тест: ${formTitle}`;
  
  let html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #4b4fcf;">Уведомление об оценке</h2>
      <p>Здравствуйте, ${studentName}!</p>
      <p>Вы получили оценку за тест: <strong>${formTitle}</strong></p>
      <div style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: #4b4fcf; margin-top: 0;">Ваша оценка: ${grade}/100</h3>
  `;
  
  if (comment) {
    html += `
        <p><strong>Комментарий преподавателя:</strong></p>
        <p style="font-style: italic; color: #666;">${comment}</p>
    `;
  }
  
  html += `
      </div>
      <p style="color: #666; font-size: 14px;">
        Это автоматическое уведомление. Пожалуйста, не отвечайте на это письмо.
      </p>
    </div>
  `;

  const mailOptions = {
    from: 'your-email@gmail.com',
    to: studentEmail,
    subject: subject,
    html: html
  };

  return transporter.sendMail(mailOptions);
}

// Запуск сервера
app.listen(port, () => {
  console.log(`🚀 Сервер запущен на порту ${port}`);
});
