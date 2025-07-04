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

// Обработчик отправки ответов студента
app.post('/submit-answer/:formId', upload.single('file'), async (req, res) => {
    try {
        const formId = req.params.formId;
        const userId = req.session.userId;
        
        if (!userId) {
            return res.status(401).json({ error: 'Не авторизован' });
        }

        console.log('Получена форма:', formId);
        console.log('Данные формы:', req.body);
        console.log('Файл:', req.file);

        // Получаем форму и вопросы
        const form = await db.query(
            'SELECT * FROM form_templates WHERE id = $1',
            [formId]
        );

        if (form.rows.length === 0) {
            return res.status(404).json({ error: 'Форма не найдена' });
        }

        const questions = await db.query(
            'SELECT * FROM questions WHERE form_id = $1 ORDER BY question_order',
            [formId]
        );

        // Проверяем, не отправлял ли уже студент эту форму
        const existingResponse = await db.query(
            'SELECT id FROM form_responses WHERE user_id = $1 AND form_id = $2',
            [userId, formId]
        );

        if (existingResponse.rows.length > 0) {
            return res.status(400).json({ error: 'Вы уже отправили эту форму' });
        }

        // Начинаем транзакцию
        await db.query('BEGIN');

        try {
            // Создаем запись о том, что форма отправлена
            const responseResult = await db.query(
                'INSERT INTO form_responses (user_id, form_id) VALUES ($1, $2) RETURNING id',
                [userId, formId]
            );

            // Обрабатываем каждый вопрос
            for (let i = 0; i < questions.rows.length; i++) {
                const question = questions.rows[i];
                const answerKey = `answer_${i}`;
                
                let answerValue = req.body[answerKey];
                let selectedOptions = null;

                // Обработка разных типов ответов
                if (question.question_type === 'checkbox') {
                    // Для чекбоксов может быть массив значений
                    if (Array.isArray(answerValue)) {
                        selectedOptions = answerValue;
                        answerValue = answerValue.join(', ');
                    } else if (answerValue) {
                        selectedOptions = [answerValue];
                    } else {
                        selectedOptions = [];
                        answerValue = '';
                    }
                } else if (question.question_type === 'file_upload') {
                    // Для файлов проверяем, есть ли загруженный файл
                    if (req.file) {
                        answerValue = req.file.filename;
                    } else {
                        answerValue = '';
                    }
                } else {
                    // Для остальных типов вопросов
                    if (!answerValue) {
                        answerValue = '';
                    }
                }

                // Сохраняем ответ
                await db.query(
                    `INSERT INTO answers (student_id, form_id, question_id, answer_text, selected_options) 
                     VALUES ($1, $2, $3, $4, $5)`,
                    [userId, formId, question.id, answerValue, selectedOptions]
                );
            }

            // Подтверждаем транзакцию
            await db.query('COMMIT');

            console.log('Форма успешно отправлена');
            res.json({ 
                success: true, 
                message: 'Форма успешно отправлена!' 
            });

        } catch (error) {
            // Откатываем транзакцию в случае ошибки
            await db.query('ROLLBACK');
            throw error;
        }

    } catch (error) {
        console.error('Ошибка при отправке формы:', error);
        res.status(500).json({ 
            error: 'Ошибка при отправке формы',
            details: error.message 
        });
    }
});

// Дополнительно: обработчик для получения отправленных форм студента
app.get('/my-submissions', async (req, res) => {
    try {
        const userId = req.session.userId;
        
        if (!userId) {
            return res.redirect('/');
        }

        const submissions = await db.query(`
            SELECT 
                ft.id,
                ft.title,
                fr.submitted_at,
                g.grade,
                g.comment
            FROM form_responses fr
            JOIN form_templates ft ON fr.form_id = ft.id
            LEFT JOIN grades g ON g.form_id = ft.id AND g.student_id = fr.user_id
            WHERE fr.user_id = $1
            ORDER BY fr.submitted_at DESC
        `, [userId]);

        res.render('my-submissions', {
            submissions: submissions.rows,
            user: req.session.user
        });

    } catch (error) {
        console.error('Ошибка при получении отправленных форм:', error);
        res.status(500).send('Ошибка сервера');
    }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`🚀 Сервер запущен на порту ${port}`);
});
