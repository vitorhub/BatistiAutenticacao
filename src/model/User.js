const mongoose = require("mongoose")

const User = mongoose.model("User",{ // define um model de nome person com tres valores
    name: String,       // name, salary e approved
    email: String,
    password: String
})

module.exports = User