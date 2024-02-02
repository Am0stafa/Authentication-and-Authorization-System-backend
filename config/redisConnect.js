const Redis = require('ioredis');

const redis = new Redis(`rediss://default:${process.env.REDIS}@eu2-proper-krill-31883.upstash.io:31883`);

redis.on('error', (err) => {
  console.log('Redis error: ' + err);
} );

module.exports = redis;
