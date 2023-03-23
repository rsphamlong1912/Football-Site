var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var userSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password:  {
        type: String,
        required: true
    },
    name:  {
        type: String,
        default: "User Name"
    },
    YOB:  {
        type: String,
        default:"2001"
    },
    isAdmin:  {
        type: Boolean,
        required: true,
        default: false
    }
},
{timestamps: true});

module.exports = mongoose.model('users', userSchema);
