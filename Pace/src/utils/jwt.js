const jwt = require('jsonwebtoken');

const signAccess = (payload) =>
    jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {expiresIn: '15m'});

const signRefresh = (payload) =>
    jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {expiresIn: '7d'});

const verifyAccess = (token) =>
    jwt.verify(token, process.env.JWT_ACCESS_SECRET);

const verifyRefresh = (token) =>
    jwt.verify(token, process.env.JWT_REFRESH_SECRET);

module.exports = {signAccess, signRefresh, verifyAccess, verifyRefresh};
