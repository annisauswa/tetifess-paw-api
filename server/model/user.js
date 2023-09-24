const mongoose = require('mongoose')
const Schema = mongoose.Schema

const userSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password:{
        type: String
    },
    name: {
        type: String,
        required: true,
    },
    bio: {
        type: String,
        required: false
    },
    date_created: {
        type: Date,
        required: true
    },
    date_edited: {
        type: Date,
        required: false
    }
})
userSchema.methods.hashPassword = function(password){
    return bcrypt.hashSync(password, 10)
}
userSchema.methods.validatePassword = function(password, hash){
    return bcrypt.compareSync(password, hash)
}


module.exports = mongoose.model('User', userSchema)
