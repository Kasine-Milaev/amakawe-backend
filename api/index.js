const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const { Resend } = require('resend')
const { Pool } = require('pg')

const app = express()

app.use(cors({
  origin: true,
  credentials: true
}))
app.use(express.json())

const BOT_TOKEN = process.env.BOT_TOKEN
const JWT_SECRET = process.env.JWT_SECRET || 'amakawe-secret-key-change-me'

const resend = new Resend(process.env.RESEND_API_KEY)

console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'Set' : 'NOT SET')

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false
})

const verificationCodes = new Map()

const createTables = async () => {
  try {
    console.log('Trying to connect to database...')
    const client = await pool.connect()
    console.log('Database connected!')
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        provider VARCHAR(50) NOT NULL,
        telegram_id VARCHAR(255) UNIQUE,
        email VARCHAR(255) UNIQUE,
        username VARCHAR(255),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        photo_url TEXT,
        password_hash VARCHAR(255),
        avatar TEXT,
        banner TEXT,
        bio TEXT,
        rating INTEGER DEFAULT 0,
        anime_count INTEGER DEFAULT 0,
        comments_count INTEGER DEFAULT 0,
        favorites INTEGER[] DEFAULT '{}',
        history JSONB DEFAULT '[]',
        anime_lists JSONB DEFAULT '{}',
        is_premium BOOLEAN DEFAULT false,
        last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `)
    
    client.release()
    console.log('Database tables created')
  } catch (error) {
    console.error('❌ Database error:', error.message)
    console.error('Full error:', error)
  }
}

createTables()

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
  console.log('Attempting to send email to:', email)
  console.log('RESEND_API_KEY:', process.env.RESEND_API_KEY ? 'Set' : 'NOT SET')
  console.log('RESEND_FROM_EMAIL:', process.env.RESEND_FROM_EMAIL)
  
  try {
    const { data, error } = await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL || 'Amakawe <onboarding@resend.dev>',
      to: email,
      subject: 'Код подтверждения Amakawe',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5;">
          <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #667eea; margin-top: 0;">Amakawe</h2>
            <p style="color: #333; font-size: 16px;">Привет!</p>
            <p style="color: #333; font-size: 16px;">Ваш код подтверждения:</p>
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; font-size: 28px; font-weight: bold; border-radius: 8px; margin: 20px 0; letter-spacing: 5px;">
              ${code}
            </div>
            <p style="color: #718096; font-size: 14px;">Код действителен 10 минут.</p>
            <p style="color: #718096; font-size: 14px;">Если вы не запрашивали этот код, просто проигнорируйте письмо.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p style="color: #718096; font-size: 14px; margin: 0;">Команда Amakawe</p>
          </div>
        </div>
      `
    })

    if (error) {
      console.error('Resend API Error:', error)
      return false
    }

    console.log('Email sent successfully:', data.id)
    return true
  } catch (error) {
    console.error('Email sending failed:', error.message)
    console.error('Full error:', error)
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
    
    let result = await pool.query(
      'SELECT * FROM users WHERE telegram_id = $1',
      [telegramData.id.toString()]
    )
    
    let user = result.rows[0]
    
    if (!user) {
      result = await pool.query(
        `INSERT INTO users (provider, telegram_id, username, first_name, last_name, photo_url, is_premium, last_login)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         RETURNING *`,
        [
          'telegram',
          telegramData.id.toString(),
          telegramData.username || null,
          telegramData.first_name,
          telegramData.last_name || null,
          telegramData.photo_url || null,
          telegramData.is_premium || false
        ]
      )
      user = result.rows[0]
      console.log('New Telegram user created:', user.id)
    } else {
      await pool.query(
        `UPDATE users SET 
          username = $1, 
          photo_url = $2, 
          last_login = NOW() 
         WHERE id = $3`,
        [
          telegramData.username || user.username,
          telegramData.photo_url || user.photo_url,
          user.id
        ]
      )
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
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        rating: user.rating,
        anime_count: user.anime_count,
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
    
    const verificationToken = jwt.sign(
      { email, code },
      JWT_SECRET,
      { expiresIn: '10m' }
    )
    
    const sent = await sendVerificationEmail(email, code)
    
    if (!sent) {
      return res.status(500).json({ error: 'Failed to send verification code' })
    }
    
    res.json({
      success: true,
      message: 'Verification code sent',
      verificationToken
    })
  } catch (error) {
    console.error('Request code error:', error)
    res.status(500).json({ error: 'Failed to send verification code' })
  }
})

app.post('/api/auth/email/verify-code', async (req, res) => {
  try {
    const { email, code, verificationToken } = req.body
    
    if (!verificationToken) {
      return res.status(400).json({ error: 'Verification token required' })
    }
    
    let decoded
    try {
      decoded = jwt.verify(verificationToken, JWT_SECRET)
    } catch (err) {
      return res.status(400).json({ error: 'Code expired or invalid' })
    }
    
    if (decoded.code !== code) {
      return res.status(400).json({ error: 'Invalid code' })
    }
    
    if (decoded.email !== email) {
      return res.status(400).json({ error: 'Email mismatch' })
    }
    
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )
    
    const user = result.rows[0]
    
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
          avatar: user.avatar,
          banner: user.banner,
          bio: user.bio,
          rating: user.rating,
          anime_count: user.anime_count,
          favorites: user.favorites,
          history: user.history
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
    
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )
    
    let user = result.rows[0]
    
    if (user && user.password_hash) {
      return res.status(400).json({ error: 'User already exists' })
    }
    
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex')
    
    if (!user) {
      result = await pool.query(
        `INSERT INTO users (provider, email, username, password_hash, last_login)
         VALUES ($1, $2, $3, $4, NOW())
         RETURNING *`,
        [
          'email',
          email,
          username || email.split('@')[0],
          passwordHash
        ]
      )
      user = result.rows[0]
      console.log('New email user created:', user.id)
    } else {
      await pool.query(
        `UPDATE users SET 
          password_hash = $1, 
          last_login = NOW() 
         WHERE id = $2`,
        [passwordHash, user.id]
      )
    }
    
    const token = generateToken(user)
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        provider: user.provider,
        email: user.email,
        username: user.username,
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        rating: user.rating,
        anime_count: user.anime_count,
        favorites: user.favorites,
        history: user.history
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
    
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )
    
    const user = result.rows[0]
    
    if (!user || !user.password_hash) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex')
    
    if (user.password_hash !== passwordHash) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    
    await pool.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    )
    
    const token = generateToken(user)
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        provider: user.provider,
        email: user.email,
        username: user.username,
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        rating: user.rating,
        anime_count: user.anime_count,
        favorites: user.favorites,
        history: user.history
      }
    })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ error: 'Login failed' })
  }
})

app.get('/api/auth/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [decoded.id]
    )
    const user = result.rows[0]
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
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        rating: user.rating,
        anime_count: user.anime_count,
        comments_count: user.comments_count,
        favorites: user.favorites,
        history: user.history,
        anime_lists: user.anime_lists
      }
    })
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' })
  }
})

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      database: 'connected'
    })
  } catch (error) {
    res.json({ 
      status: 'error',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message
    })
  }
})

app.get('/', (req, res) => {
  res.json({ message: 'Amakawe Backend API is running' })
})

app.get('/api/profile/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [req.params.id]
    )
    
    const user = result.rows[0]
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    
    res.json({
      success: true,
      user: {
        id: user.id,
        provider: user.provider,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        photo_url: user.photo_url,
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        rating: user.rating,
        anime_count: user.anime_count,
        comments_count: user.comments_count,
        favorites: user.favorites,
        history: user.history,
        anime_lists: user.anime_lists,
        created_at: user.created_at,
        last_login: user.last_login
      }
    })
  } catch (error) {
    console.error('Profile error:', error)
    res.status(500).json({ error: 'Failed to get profile' })
  }
})

app.get('/api/profile/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [decoded.id]
    )
    const user = result.rows[0]
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
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        rating: user.rating,
        anime_count: user.anime_count,
        comments_count: user.comments_count,
        favorites: user.favorites,
        history: user.history,
        anime_lists: user.anime_lists,
        created_at: user.created_at,
        last_login: user.last_login
      }
    })
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' })
  }
})

app.put('/api/profile/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const { username, bio, avatar, banner } = req.body
    
    const updates = []
    const values = []
    let paramCount = 1
    
    if (username !== undefined) {
      updates.push(`username = $${paramCount}`)
      values.push(username)
      paramCount++
    }
    if (bio !== undefined) {
      updates.push(`bio = $${paramCount}`)
      values.push(bio)
      paramCount++
    }
    if (avatar !== undefined) {
      updates.push(`avatar = $${paramCount}`)
      values.push(avatar)
      paramCount++
    }
    if (banner !== undefined) {
      updates.push(`banner = $${paramCount}`)
      values.push(banner)
      paramCount++
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' })
    }
    
    updates.push(`updated_at = CURRENT_TIMESTAMP`)
    values.push(decoded.id)
    
    const result = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    )
    
    const user = result.rows[0]
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        bio: user.bio,
        avatar: user.avatar,
        banner: user.banner,
        rating: user.rating,
        anime_count: user.anime_count
      }
    })
  } catch (error) {
    console.error('Update profile error:', error)
    res.status(500).json({ error: 'Failed to update profile' })
  }
})

app.post('/api/profile/me/activity', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const { animeId, action } = req.body
    
    if (!animeId || !action) {
      return res.status(400).json({ error: 'animeId and action required' })
    }
    
    let user = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id])
    const currentUser = user.rows[0]
    
    let history = currentUser.history || []
    let animeLists = currentUser.anime_lists || {}
    let animeCount = currentUser.anime_count || 0
    
    history.unshift({
      animeId,
      action,
      viewedAt: new Date().toISOString()
    })
    
    if (history.length > 50) {
      history = history.slice(0, 50)
    }
    
    if (action === 'watching' || action === 'completed' || action === 'planned' || action === 'dropped' || action === 'on_hold') {
      if (!animeLists.watching) animeLists.watching = []
      if (!animeLists.planned) animeLists.planned = []
      if (!animeLists.completed) animeLists.completed = []
      if (!animeLists.onHold) animeLists.onHold = []
      if (!animeLists.dropped) animeLists.dropped = []
      
      const allLists = ['watching', 'planned', 'completed', 'onHold', 'dropped']
      allLists.forEach(list => {
        animeLists[list] = animeLists[list].filter(id => id !== animeId)
      })
      
      const listMap = {
        'watching': 'watching',
        'completed': 'completed',
        'planned': 'planned',
        'dropped': 'dropped',
        'on_hold': 'onHold'
      }
      
      const targetList = listMap[action]
      if (targetList && !animeLists[targetList].includes(animeId)) {
        animeLists[targetList].push(animeId)
      }
      
      if (action === 'completed') {
        animeCount += 1
      }
    }
    
    await pool.query(
      'UPDATE users SET history = $1, anime_lists = $2, anime_count = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
      [JSON.stringify(history), JSON.stringify(animeLists), animeCount, decoded.id]
    )
    
    res.json({
      success: true,
      history,
      animeLists,
      animeCount
    })
  } catch (error) {
    console.error('Activity error:', error)
    res.status(500).json({ error: 'Failed to update activity' })
  }
})

app.get('/api/profile/:id/activity', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT history, anime_lists, anime_count FROM users WHERE id = $1',
      [req.params.id]
    )
    
    const user = result.rows[0]
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    
    res.json({
      success: true,
      activity: {
        history: user.history || [],
        animeLists: user.anime_lists || {},
        animeCount: user.anime_count || 0
      }
    })
  } catch (error) {
    console.error('Activity error:', error)
    res.status(500).json({ error: 'Failed to get activity' })
  }
})

app.post('/api/profile/me/avatar', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const { avatar } = req.body
    
    if (!avatar) {
      return res.status(400).json({ error: 'Avatar URL required' })
    }
    
    await pool.query(
      'UPDATE users SET avatar = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [avatar, decoded.id]
    )
    
    res.json({
      success: true,
      avatar
    })
  } catch (error) {
    console.error('Avatar error:', error)
    res.status(500).json({ error: 'Failed to update avatar' })
  }
})

app.post('/api/profile/me/banner', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({ error: 'No token provided' })
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    const { banner } = req.body
    
    if (!banner) {
      return res.status(400).json({ error: 'Banner URL required' })
    }
    
    await pool.query(
      'UPDATE users SET banner = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [banner, decoded.id]
    )
    
    res.json({
      success: true,
      banner
    })
  } catch (error) {
    console.error('Banner error:', error)
    res.status(500).json({ error: 'Failed to update banner' })
  }
})



module.exports = app