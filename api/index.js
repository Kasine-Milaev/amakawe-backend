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
      try {
        await axios.post(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          chat_id: userId,
          text: `👋 Привет, ${user.first_name}!\n\nДобро пожаловать в Amakawe! 🎌`
        })
      } catch (err) {
        console.error('Failed to send welcome message:', err.message)
      }
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

app.get('/api/auth/google', (req, res) => {
  const frontendUrl = process.env.FRONTEND_URL || 'https://amakawe.ru'
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${process.env.GOOGLE_CLIENT_ID}&` +
    `redirect_uri=${frontendUrl}/auth/callback&` +
    `response_type=code&` +
    `scope=profile email&` +
    `access_type=offline`
  res.json({ authUrl: googleAuthUrl })
})

app.post('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.body
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${process.env.FRONTEND_URL}/auth/callback`,
      grant_type: 'authorization_code'
    })
    const userRes = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
    })
    const googleUser = userRes.data
    const userId = `google_${googleUser.id}`
    let user = usersDB.get(userId)
    if (!user) {
      user = {
        id: userId,
        provider: 'google',
        email: googleUser.email,
        username: googleUser.email.split('@')[0],
        first_name: googleUser.given_name || '',
        last_name: googleUser.family_name || '',
        photo_url: googleUser.picture || null,
        language_code: 'ru',
        is_premium: false,
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
        favorites: [],
        history: []
      }
      usersDB.set(userId, user)
    } else {
      user.last_login = new Date().toISOString()
      user.photo_url = googleUser.picture || user.photo_url
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
        email: user.email,
        favorites: user.favorites
      }
    })
  } catch (error) {
    console.error('Google auth error:', error.message)
    res.status(500).json({ error: 'Google authentication failed' })
  }
})

app.get('/api/auth/vk', (req, res) => {
  const frontendUrl = process.env.FRONTEND_URL || 'https://amakawe.ru'
  const vkAuthUrl = `https://oauth.vk.com/authorize?` +
    `client_id=${process.env.VK_CLIENT_ID}&` +
    `redirect_uri=${frontendUrl}/auth/callback&` +
    `response_type=code&` +
    `scope=email&` +
    `v=5.131`
  res.json({ authUrl: vkAuthUrl })
})

app.post('/api/auth/vk/callback', async (req, res) => {
  try {
    const { code } = req.body
    const tokenRes = await axios.post('https://oauth.vk.com/access_token', {
      client_id: process.env.VK_CLIENT_ID,
      client_secret: process.env.VK_CLIENT_SECRET,
      redirect_uri: `${process.env.FRONTEND_URL}/auth/callback`,
      code,
      grant_type: 'authorization_code'
    })
    const accessToken = tokenRes.data.access_token
    const userId = tokenRes.data.user_id
    const userRes = await axios.get('https://api.vk.com/method/users.get', {
      params: {
        user_ids: userId,
        fields: 'photo_200,first_name,last_name',
        access_token: accessToken,
        v: '5.131'
      }
    })
    const vkUser = userRes.data.response[0]
    const dbUserId = `vk_${userId}`
    let user = usersDB.get(dbUserId)
    if (!user) {
      user = {
        id: dbUserId,
        provider: 'vk',
        vk_id: userId,
        username: `vk${userId}`,
        first_name: vkUser.first_name || '',
        last_name: vkUser.last_name || '',
        photo_url: vkUser.photo_200 || null,
        language_code: 'ru',
        is_premium: false,
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
        favorites: [],
        history: []
      }
      usersDB.set(dbUserId, user)
    } else {
      user.last_login = new Date().toISOString()
      user.photo_url = vkUser.photo_200 || user.photo_url
      usersDB.set(dbUserId, user)
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
        favorites: user.favorites
      }
    })
  } catch (error) {
    console.error('VK auth error:', error.message)
    res.status(500).json({ error: 'VK authentication failed' })
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
        first_name: user.first_name,
        last_name: user.last_name,
        photo_url: user.photo_url,
        email: user.email,
        favorites: user.favorites,
        history: user.history
      }
    })
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' })
  }
})

app.get('/api/user/:id', (req, res) => {
  const user = usersDB.get(req.params.id)
  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }
  res.json({
    id: user.id,
    username: user.username,
    first_name: user.first_name,
    last_name: user.last_name,
    photo_url: user.photo_url,
    is_premium: user.is_premium,
    favorites: user.favorites,
    history: user.history
  })
})

app.post('/api/user/:id/favorites', (req, res) => {
  const user = usersDB.get(req.params.id)
  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }
  const { animeId, title } = req.body
  if (!user.favorites.find(f => f.id === animeId)) {
    user.favorites.push({ id: animeId, title, added_at: new Date().toISOString() })
    usersDB.set(req.params.id, user)
  }
  res.json({ success: true, favorites: user.favorites })
})

app.delete('/api/user/:id/favorites/:animeId', (req, res) => {
  const user = usersDB.get(req.params.id)
  if (!user) {
    return res.status(404).json({ error: 'User not found' })
  }
  user.favorites = user.favorites.filter(f => f.id !== req.params.animeId)
  usersDB.set(req.params.id, user)
  res.json({ success: true, favorites: user.favorites })
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