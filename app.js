const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const port = 3000;

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: '3141',
  port: 5432,
});

//app.use(morgan('dev'))
//app.use(express.static(path.join(__dirname, '/public')))
app.use('/public', express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session middleware setup
app.use(session({
  secret: 'aBcDeFgHiJ',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }, // 30 days
}));

app.get('/page1', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/page2', (req, res) => {
  res.sendFile(__dirname + '/public/signin.html');
});

app.get('/test1', (req, res) => {
  res.sendFile(__dirname + '/public/test1.html');
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/main.html');
});

app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *';
  const values = [username, email, hashedPassword, role];

  try {
    const result = await pool.query(query, values);

    req.session.user = { id: result.rows[0].id, role: result.rows[0].role };

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error registering user');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const query = 'SELECT * FROM users WHERE username = $1';
  const values = [username];

  try {
    const result = await pool.query(query, values);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        req.session.user = { id: user.id, role: user.role };

        // Redirect the user based on their role
        if (user.role === 'admin') {
          res.redirect('/admin-content');
        } else if (user.role === 'moderator') {
          res.redirect('/moderator-content');
        } else if (user.role === 'user'){
          res.redirect('/user-content');
        }
      } else {
        //res.status(401).send('Invalid password');
        res.status(401).json({ error: 'Invalid password' });
      }
    } else {
      //res.status(404).send('User not found');
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    //res.status(500).send('Error during login');
    res.status(500).json({ error: 'Error during login' });
  }
});


const checkRole = (requiredRoles) => {
  return (req, res, next) => {
    const userRole = req.session.user ? req.session.user.role : null;

    if (requiredRoles.includes(userRole)) {
      next();
    } else {
      res.status(403).json({ message: 'Access forbidden. Insufficient privileges.' });
    }
  };
};

app.get('/admin-content', checkRole(['admin']), (req, res) => {
  res.sendFile(__dirname + '/public/admin.html');
});

app.get('/moderator-content', checkRole(['admin', 'moderator']), (req, res) => {
  res.sendFile(__dirname + '/public/moderator.html');
});

app.get('/user-content', checkRole(['admin', 'moderator', 'user']), (req, res) => {
  res.sendFile(__dirname + '/public/user.html');
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      res.status(500).send('Error during logout');
    } else {
      res.redirect('/');
    }
  });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
