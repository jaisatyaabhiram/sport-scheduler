const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin
const serviceAccount = require('./config/key.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
});

const db = admin.firestore();

const app = express();

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'sport-scheduler-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// Make user available to all views
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

// User model
class User {
  constructor(id, email, password, name, role) {
    this.id = id;
    this.email = email;
    this.password = password;
    this.name = name;
    this.role = role;
  }

  static async create(userData) {
    const usersRef = db.collection('users');
    const docRef = await usersRef.add(userData);
    return docRef.id;
  }

  static async findByEmail(email) {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();
    if (snapshot.empty) return null;
    
    const doc = snapshot.docs[0];
    return { id: doc.id, ...doc.data() };
  }

  static async findById(id) {
    const userDoc = await db.collection('users').doc(id).get();
    if (!userDoc.exists) return null;
    return { id: userDoc.id, ...userDoc.data() };
  }

  validPassword(password) {
    return bcrypt.compareSync(password, this.password);
  }
}

// Passport configuration
passport.use('local', new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findByEmail(email);
      if (!user) {
        return done(null, false, { message: 'Incorrect email or password.' });
      }
      
      const isValidPassword = bcrypt.compareSync(password, user.password);
      if (!isValidPassword) {
        return done(null, false, { message: 'Incorrect email or password.' });
      }
      
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Custom middleware for role-based access
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.status(401).render('error', { message: 'Unauthorized access. Admin privileges required.' });
}

function requirePlayer(req, res, next) {
  if (req.isAuthenticated() && (req.user.role === 'player' || req.user.role === 'admin')) {
    return next();
  }
  res.status(401).render('error', { message: 'Please log in to access this page.' });
}

// Routes

// Home route
app.get('/', (req, res) => {
  res.render('index');
});

// Auth routes
// Auth routes
app.get('/login', (req, res) => {
  res.render('auth/login', { error: null });
});

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render('auth/login', { error: info.message || 'Invalid credentials' });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

app.get('/register', (req, res) => {
  res.render('auth/register');
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Basic validation
    if (!name || !email || !password) {
      return res.render('auth/register', { error: 'All fields are required' });
    }
    
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.render('auth/register', { error: 'Email already registered' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'player',
      createdAt: new Date()
    });

    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.render('auth/register', { error: 'Registration failed. Please try again.' });
  }
});
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Dashboard route
app.get('/dashboard', requirePlayer, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const sports = await db.collection('sports').where('createdBy', '==', req.user.id).get();
      const sportsList = sports.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      
      res.render('admin/dashboard', { 
        sports: sportsList 
      });
    } else {
      // Player dashboard
      const createdSessions = await db.collection('sessions')
        .where('createdBy', '==', req.user.id)
        .get();
      
      const joinedSessions = await db.collection('sessions')
        .where('players', 'array-contains', req.user.id)
        .get();

      const availableSessions = await db.collection('sessions')
        .where('dateTime', '>=', new Date())
        .get();

      res.render('player/dashboard', {
        createdSessions: createdSessions.docs.map(doc => ({ id: doc.id, ...doc.data() })),
        joinedSessions: joinedSessions.docs.map(doc => ({ id: doc.id, ...doc.data() })),
        availableSessions: availableSessions.docs.map(doc => ({ id: doc.id, ...doc.data() }))
      });
    }
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error loading dashboard' });
  }
});

// Admin routes
app.get('/admin/sports', requireAdmin, async (req, res) => {
  try {
    const sports = await db.collection('sports').where('createdBy', '==', req.user.id).get();
    res.render('admin/sports', {
      sports: sports.docs.map(doc => ({ id: doc.id, ...doc.data() }))
    });
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error loading sports' });
  }
});

app.post('/admin/sports', requireAdmin, async (req, res) => {
  try {
    const { name } = req.body;
    await db.collection('sports').add({
      name,
      createdBy: req.user.id,
      createdAt: new Date()
    });
    res.redirect('/admin/sports');
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error creating sport' });
  }
});

app.get('/admin/reports', requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let sessionsQuery = db.collection('sessions');
    
    if (startDate && endDate) {
      sessionsQuery = sessionsQuery
        .where('dateTime', '>=', new Date(startDate))
        .where('dateTime', '<=', new Date(endDate));
    }

    const sessions = await sessionsQuery.get();
    const sessionsData = sessions.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    // Calculate sports popularity
    const sportsCount = {};
    sessionsData.forEach(session => {
      sportsCount[session.sport] = (sportsCount[session.sport] || 0) + 1;
    });

    res.render('admin/reports', {
      sessions: sessionsData,
      sportsCount,
      startDate,
      endDate
    });
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error generating reports' });
  }
});

// Session routes
app.get('/sessions/create', requirePlayer, async (req, res) => {
  try {
    const sports = await db.collection('sports').get();
    res.render('player/create-session', {
      sports: sports.docs.map(doc => ({ id: doc.id, ...doc.data() }))
    });
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error loading create session page' });
  }
});

app.post('/sessions/create', requirePlayer, async (req, res) => {
  try {
    const { sport, teamAPlayers, teamBPlayers, additionalPlayers, dateTime, venue } = req.body;
    
    await db.collection('sessions').add({
      sport,
      teamAPlayers: teamAPlayers ? teamAPlayers.split(',') : [],
      teamBPlayers: teamBPlayers ? teamBPlayers.split(',') : [],
      additionalPlayers: parseInt(additionalPlayers) || 0,
      dateTime: new Date(dateTime),
      venue,
      createdBy: req.user.id,
      players: [req.user.id],
      status: 'active',
      createdAt: new Date()
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error creating session' });
  }
});

app.post('/sessions/:id/join', requirePlayer, async (req, res) => {
  try {
    const sessionId = req.params.id;
    const sessionRef = db.collection('sessions').doc(sessionId);
    const sessionDoc = await sessionRef.get();
    
    if (!sessionDoc.exists) {
      return res.render('error', { message: 'Session not found' });
    }

    const session = sessionDoc.data();
    
    // Check if session is in the past
    if (new Date(session.dateTime) < new Date()) {
      return res.render('error', { message: 'Cannot join past sessions' });
    }

    // Check if user already joined
    if (session.players.includes(req.user.id)) {
      return res.redirect('/dashboard');
    }

    await sessionRef.update({
      players: admin.firestore.FieldValue.arrayUnion(req.user.id)
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error joining session' });
  }
});

app.post('/sessions/:id/cancel', requirePlayer, async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { reason } = req.body;
    const sessionRef = db.collection('sessions').doc(sessionId);
    const sessionDoc = await sessionRef.get();
    
    if (!sessionDoc.exists) {
      return res.render('error', { message: 'Session not found' });
    }

    const session = sessionDoc.data();
    
    // Check if user is the creator
    if (session.createdBy !== req.user.id && req.user.role !== 'admin') {
      return res.render('error', { message: 'Only session creator can cancel the session' });
    }

    await sessionRef.update({
      status: 'cancelled',
      cancellationReason: reason,
      cancelledAt: new Date()
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render('error', { message: 'Error cancelling session' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});