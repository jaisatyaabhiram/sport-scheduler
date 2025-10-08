const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const path = require('path');

// Suppress verbose Firebase logs
process.env.FIREBASE_DEBUG = false;
process.env.GRPC_VERBOSITY = 'NONE';

// Initialize Firebase Admin with better error handling
let db;
try {
  const serviceAccount = require('./config/key.json');
  
  // Check if service account is properly configured
  if (!serviceAccount.project_id) {
    throw new Error('Firebase service account configuration is invalid');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
  });

  db = admin.firestore();
  
  // Test the connection
  db.collection('test').doc('test').get()
    .then(() => {
      console.log('✅ Firebase Firestore connected successfully');
    })
    .catch((error) => {
      console.error('❌ Firebase Firestore connection failed:', error.message);
    });

} catch (error) {
  console.error('❌ Firebase initialization failed:', error.message);
  process.exit(1);
}

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
    try {
      const usersRef = db.collection('users');
      const docRef = await usersRef.add(userData);
      console.log('✅ User created with ID:', docRef.id);
      return docRef.id;
    } catch (error) {
      console.error('❌ Error creating user:', error);
      throw new Error('Failed to create user');
    }
  }

  static async findByEmail(email) {
    try {
      const usersRef = db.collection('users');
      const snapshot = await usersRef.where('email', '==', email).get();
      if (snapshot.empty) return null;
      
      const doc = snapshot.docs[0];
      return { id: doc.id, ...doc.data() };
    } catch (error) {
      console.error('❌ Error finding user by email:', error);
      throw new Error('Database error');
    }
  }

  static async findById(id) {
    try {
      const userDoc = await db.collection('users').doc(id).get();
      if (!userDoc.exists) return null;
      return { id: userDoc.id, ...userDoc.data() };
    } catch (error) {
      console.error('❌ Error finding user by ID:', error);
      throw new Error('Database error');
    }
  }

  static async getAllPlayers() {
    try {
      const usersRef = db.collection('users');
      const snapshot = await usersRef.where('role', '==', 'player').get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    } catch (error) {
      console.error('❌ Error getting all players:', error);
      throw new Error('Database error');
    }
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
app.get('/login', (req, res) => {
  res.render('auth/login', { error: null });
});

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render('auth/login', { 
        error: info && info.message ? info.message : 'Invalid email or password' 
      });
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
  res.render('auth/register', { error: null });
});

app.post('/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Basic validation
    if (!name || !email || !password) {
      return res.render('auth/register', { error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.render('auth/register', { error: 'Password must be at least 6 characters long' });
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
    console.error('Registration error:', error);
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
      
      // Get sessions with applications
      const sessionsSnapshot = await db.collection('sessions').get();
      const sessionsWithApplications = [];
      
      for (let doc of sessionsSnapshot.docs) {
        const sessionData = { id: doc.id, ...doc.data() };
        const applications = await db.collection('sessionApplications')
          .where('sessionId', '==', doc.id)
          .where('status', '==', 'pending')
          .get();
        
        sessionData.pendingApplications = applications.docs.map(appDoc => ({
          id: appDoc.id,
          ...appDoc.data()
        }));
        
        sessionsWithApplications.push(sessionData);
      }
      
      res.render('admin/dashboard', { 
        sports: sportsList,
        sessions: sessionsWithApplications
      });
    } else {
      // Player dashboard - can only view and apply to sessions
      const appliedApplications = await db.collection('sessionApplications')
        .where('playerId', '==', req.user.id)
        .get();

      const appliedSessionIds = appliedApplications.docs.map(doc => doc.data().sessionId);
      
      const availableSessions = await db.collection('sessions')
        .where('dateTime', '>=', new Date())
        .where('status', '==', 'active')
        .get();

      // Get session details for applied sessions
      const appliedSessionDetails = [];
      for (let applicationDoc of appliedApplications.docs) {
        const application = applicationDoc.data();
        const sessionDoc = await db.collection('sessions').doc(application.sessionId).get();
        if (sessionDoc.exists) {
          appliedSessionDetails.push({
            id: sessionDoc.id,
            ...sessionDoc.data(),
            application: { id: applicationDoc.id, ...application }
          });
        }
      }

      res.render('player/dashboard', {
        availableSessions: availableSessions.docs.map(doc => ({ 
          id: doc.id, 
          ...doc.data(),
          hasApplied: appliedSessionIds.includes(doc.id)
        })),
        appliedSessions: appliedSessionDetails
      });
    }
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).render('error', { 
      message: 'Error loading dashboard. Please try again later.' 
    });
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
    console.error('Sports load error:', error);
    res.status(500).render('error', { message: 'Error loading sports' });
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
    console.error('Sport creation error:', error);
    res.status(500).render('error', { message: 'Error creating sport' });
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
    console.error('Reports error:', error);
    res.status(500).render('error', { message: 'Error generating reports' });
  }
});

// Session routes - Only admins can create sessions
app.get('/sessions/create', requireAdmin, async (req, res) => {
  try {
    const sports = await db.collection('sports').get();
    res.render('admin/create-session', {
      sports: sports.docs.map(doc => ({ id: doc.id, ...doc.data() }))
    });
  } catch (error) {
    console.error('Create session page error:', error);
    res.status(500).render('error', { message: 'Error loading create session page' });
  }
});

app.post('/sessions/create', requireAdmin, async (req, res) => {
  try {
    const { sport, dateTime, venue, maxPlayers } = req.body;
    
    await db.collection('sessions').add({
      sport,
      maxPlayers: parseInt(maxPlayers) || 10,
      dateTime: new Date(dateTime),
      venue,
      createdBy: req.user.id,
      players: [], // Initialize empty players array
      status: 'active',
      createdAt: new Date()
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Session creation error:', error);
    res.status(500).render('error', { message: 'Error creating session' });
  }
});

// Player applies to join session
app.post('/sessions/:id/apply', requirePlayer, async (req, res) => {
  try {
    const sessionId = req.params.id;
    const sessionRef = db.collection('sessions').doc(sessionId);
    const sessionDoc = await sessionRef.get();
    
    if (!sessionDoc.exists) {
      return res.status(404).render('error', { message: 'Session not found' });
    }

    const session = sessionDoc.data();
    
    // Check if session is in the past
    if (new Date(session.dateTime) < new Date()) {
      return res.status(400).render('error', { message: 'Cannot apply to past sessions' });
    }

    // Check if player already applied
    const existingApplication = await db.collection('sessionApplications')
      .where('sessionId', '==', sessionId)
      .where('playerId', '==', req.user.id)
      .get();

    if (!existingApplication.empty) {
      return res.redirect('/dashboard');
    }

    // Create application
    await db.collection('sessionApplications').add({
      sessionId,
      playerId: req.user.id,
      playerName: req.user.name,
      playerEmail: req.user.email,
      status: 'pending',
      appliedAt: new Date()
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Application error:', error);
    res.status(500).render('error', { message: 'Error applying to session' });
  }
});

// Admin manages session applications
app.get('/admin/sessions/:id/applications', requireAdmin, async (req, res) => {
  try {
    const sessionId = req.params.id;
    const sessionDoc = await db.collection('sessions').doc(sessionId).get();
    
    if (!sessionDoc.exists) {
      return res.status(404).render('error', { message: 'Session not found' });
    }

    const applications = await db.collection('sessionApplications')
      .where('sessionId', '==', sessionId)
      .get();

    const session = { id: sessionDoc.id, ...sessionDoc.data() };
    const applicationList = applications.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.render('admin/session-applications', {
      session,
      applications: applicationList
    });
  } catch (error) {
    console.error('Applications load error:', error);
    res.status(500).render('error', { message: 'Error loading applications' });
  }
});

// Admin accepts/rejects applications
app.post('/admin/applications/:id/accept', requireAdmin, async (req, res) => {
  try {
    const applicationId = req.params.id;
    const applicationRef = db.collection('sessionApplications').doc(applicationId);
    const applicationDoc = await applicationRef.get();
    
    if (!applicationDoc.exists) {
      return res.status(404).render('error', { message: 'Application not found' });
    }

    const application = applicationDoc.data();
    
    // Update application status
    await applicationRef.update({
      status: 'accepted',
      processedAt: new Date(),
      processedBy: req.user.id
    });

    // Add player to session
    const sessionRef = db.collection('sessions').doc(application.sessionId);
    await sessionRef.update({
      players: admin.firestore.FieldValue.arrayUnion(application.playerId)
    });

    res.redirect(`/admin/sessions/${application.sessionId}/applications`);
  } catch (error) {
    console.error('Accept application error:', error);
    res.status(500).render('error', { message: 'Error accepting application' });
  }
});

app.post('/admin/applications/:id/reject', requireAdmin, async (req, res) => {
  try {
    const applicationId = req.params.id;
    const applicationRef = db.collection('sessionApplications').doc(applicationId);
    const applicationDoc = await applicationRef.get();
    
    if (!applicationDoc.exists) {
      return res.status(404).render('error', { message: 'Application not found' });
    }

    const application = applicationDoc.data();
    
    // Update application status
    await applicationRef.update({
      status: 'rejected',
      processedAt: new Date(),
      processedBy: req.user.id
    });

    res.redirect(`/admin/sessions/${application.sessionId}/applications`);
  } catch (error) {
    console.error('Reject application error:', error);
    res.status(500).render('error', { message: 'Error rejecting application' });
  }
});

app.post('/sessions/:id/cancel', requireAdmin, async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { reason } = req.body;
    const sessionRef = db.collection('sessions').doc(sessionId);
    const sessionDoc = await sessionRef.get();
    
    if (!sessionDoc.exists) {
      return res.status(404).render('error', { message: 'Session not found' });
    }

    await sessionRef.update({
      status: 'cancelled',
      cancellationReason: reason,
      cancelledAt: new Date()
    });

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Cancel session error:', error);
    res.status(500).render('error', { message: 'Error cancelling session' });
  }
});

// Health check route
app.get('/health', async (req, res) => {
  try {
    // Test Firebase connection
    await db.collection('health').doc('check').set({
      timestamp: new Date(),
      status: 'ok'
    });
    
    res.json({ 
      status: 'ok', 
      database: 'connected',
      timestamp: new Date() 
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      database: 'disconnected',
      error: error.message 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).render('error', { 
    message: err.message || 'An internal server error occurred' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', { 
    message: 'Page not found' 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check available at http://localhost:${PORT}/health`);
});