const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {type: String, required: true, trim: true, maxlength: 120},
    username: {type: String, required: true, trim: true, unique: true, minlength: 3, maxlength: 40},
    email: {type: String, required: true, trim: true, unique: true, lowercase: true, maxlength: 254},
    passwordHash: {type: String, required: true},
}, {timestamps: true});

module.exports = mongoose.model('User', userSchema);
