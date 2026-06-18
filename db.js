const { Pool } = require('pg')

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
})

const createTables = async () => {
  try {
    await pool.query(`
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
    console.log('Database tables created')
  } catch (error) {
    console.error('Error creating tables:', error)
  }
}

module.exports = { pool, createTables }