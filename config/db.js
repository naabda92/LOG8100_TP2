// Check if DATABASE_URL is defined
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not defined');
}

module.exports = {
  dialect: 'postgres'
}