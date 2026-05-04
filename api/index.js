const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const axios = require('axios')
const jwt = require('jsonwebtoken')

const app = express()

app.use(cors({
  origin: true,
  credentials: true
}))
app.use(express.json())

const BOT_TOKEN = process.env.BOT_TOKEN
const JWT_SECRET = process.env.JWT_SECRET || 'amakawe-secret-key-change-me'

const usersDB = new Map()
const verificationCodes = new Map()

const validateTelegramData = (data) => {
  const { hash, ...userData } = data
  const dataCheckString = Object.keys(userData)
    .sort()
    .map(key => `${key}=${userData[key]}`)
    .join('\n')
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest()
  const hashCheck = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex')
  return hashCheck === hash
}

const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, provider: user.provider },
    JWT_SECRET,
    { expiresIn: '30d' }
  )
}

const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

const sendVerificationEmail = async (email, code) => {
  console.log(`📧 Verification code for ${email}: ${code}`)
  
  try {
    await axios.post('https://api.emailjs.com/api/v1.0/email/send', {
      service_id: process.env.EMAILJS_SERVICE_ID,
      template_id: process.env.EMAILJS_TEMPLATE_ID,
      user_id: process.env.EMAILJS_USER_ID,
      template_params: {
        to_email: email,
        verification_code: code
      }
    }, {
      headers: { 'Content-Type': 'application/json' }
    })
    return true
  } catch (error) {
    console.error('Email sending failed:', error.message)
    return false
  }
}

app.post('/api/auth/telegram', async (req, res) => {
  try {
    const telegramData = req.body
    if (!BOT_TOKEN) {
      return res.status(500).json({ error: 'BOT_TOKEN not configured' })
    }
    if (!validateTelegramData(telegramData)) {
      return res.status(401).json({ error: 'Invalid Telegram data' })
    }
    const userId = telegramData.id
    let user = usersDB.get(userId)
    if (!user) {
      user = {
        id: userId,
        provider: 'telegram',
        username: telegramData.username || null,
        first_name: telegramData.first_name,
        last_name: telegramData.last_name || null,
        photo_url: telegramData.photo_url || null,
        language_code: telegramData.language_code || 'ru',
        is_premium: telegramData.is_premium || false,
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
        favorites: [],
        history: []
      }
      usersDB.set(userId, user)
    } else {
      user.last_login = new Date().toISOString()
      user.username = telegramData.username || user.username
      user.photo_url = telegramData.photo_url || user.photo_url
      usersDB.set(userId, user)
    }
    const token = generateToken(user)
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        provider: user.provider,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        photo_url: user.photo_url,
        is_premium: user.is_premium,
        favorites: user.favorites,
        history: user.history
      }
    })
  } catch (error) {
    console.error('Auth error:', error)
    res.status(500).json({ error: 'Authentication failed' })
  }
})

app.post('/api/auth/email/request-code', async (req, res) => {
  try {
    const { email } = req.body
    
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email' })
    }
    
    const code = generateVerificationCode()
    const expiresAt = Date.now() + 10 * 60 * 1000
    
    verificationCodes.set(email, {
      code,
      expiresAt,
      attempts: 0
    })
    
    const sent = await sendVerificationEmail(email, code)
    
    if (!sent && !process.env.EMAILJS_SERVICE_ID) {
      console.log('⚠️ EmailJS not configured, code logged to console')
    }
    
    res.json({
      success: true,
      message: 'Verification code sent',
      code: process.env.NODE_ENV === 'development' ? code : undefined
    })
  } catch (error) {
    console.error('Request code error:', error)
    res.status(500).json({ error: 'Failed to send verification code' })
  }
})

app.post('/api/auth/email/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body
    
    const verification = verificationCodes.get(email)
    
    if (!verification) {
      return res.status(400).json({ error: 'Code not found or expired' })
    }
    
    if (Date.now() > verification.expiresAt) {
      verificationCodes.delete(email)
      return res.status(400).json({ error: 'Code expired' })
    }
    
    if (verification.attempts >= 3) {
      verificationCodes.delete(email)
      return res.status(400).json({ error: 'Too many attempts' })
    }
    
    if (verification.code !== code) {
      verification.attempts += 1
      return res.status(400).json({ error: 'Invalid code' })
    }
    
    verificationCodes.delete(email)
    
    let user = usersDB.get(`email_${email}`)
    
    if (!user) {
      res.json({
        success: true,
        verified: true,
        needsRegistration: true,
        email
      })
    } else {
      const token = generateToken(user)
      res.json({
        success: true,
        verified: true,
        needsRegistration: false,
        token,
        user: {
          id: user.id,
          provider: user.provider,
          email: user.email,
          username: user.username,
          favorites: user.favorites
        }
      })
    }
  } catch (error) {
    console.error('Verify code error:', error)
    res.status(500).json({ error: 'Verification failed' })
  }
})

app.post('/api/auth/email/register', async (req, res) => {
  try {
    const { email, password, username } = req.body
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' })
    }
    
    const userId = `email_${email}`
    
    let user = usersDB.get(userId)
    
    if (user && user.passwordHash) {
      return res.status(400).json({ error: 'User already exists' })
    }
    
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex')
    
    user = {
      id: userId,
      provider: 'email',
      email,
      username: username || email.split('@')[0],
      passwordHash,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      favorites: [],
      history: []
    }
    
    usersDB.set(userId, user)
    
    const token = generateToken(user)
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        provider: user.provider,
        email: user.email,
        username: user.username,
        favorites: user.favorites
      }
    })
  } catch (error) {
    console.error('Register error:', error)
    res.status(500).json({ error: 'Registration failed' })
  }
})

app.post('/api/auth/email/login', async (req, res) => {
  try {
    const { email, password } = req.body
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }
    
    const userId = `email_${email}`
    const user = usersDB.get(userId)
    
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex')
    
    if (user.passwordHash !== passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    user.last_login = new Date().toISOString()
    usersDB.set(userId, user)
    
    const token = generateToken(user)
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        provider: user.provider,
        email: user.email,
        username: user.username,
        favorites: user.favorites
      }
    })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ error: 'Login failed' })
  }
})

app.get('/api/auth/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const user = usersDB.get(decoded.id)
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    res.json({
      success: true,
      user: {
        id: user.id,
        provider: user.provider,
        username: user.username,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        photo_url: user.photo_url,
        favorites: user.favorites,
        history: user.history
      }
    })
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' })
  }
})

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    users: usersDB.size
  })
})

app.get('/', (req, res) => {
  res.json({ message: 'Amakawe Backend API is running' })
})

module.exports = app