const mongoose = require("mongoose")

const userCollection = "users"
const userShema = new mongoose.Schema({
    name: { type: String },
    username: { type: String, required: true },
    password: { type: String, required: true }
})

const User = mongoose.model(userCollection, userShema)

module.exports = User