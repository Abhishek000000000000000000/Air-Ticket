const mongoose  = require('mongoose');
const {Schema} = mongoose;

const connection = mongoose.connect(process.env.url);

const userSchema = mongoose.Schema({
        name: {type :String},
        email: {type :String},
        password: {type :String}
      
})

const userModule = mongoose.model("User" , userSchema );

const fliteSchema = mongoose.Schema({
    airline : {type :String},
    flightNo: {type :String},
    departure: {type :String},
    arrival: {type :String},
    departureTime: {type :Date},
    arrivalTime: {type :Date},
    seats: {type :Number},
    price: {type :Number}
})
const fliteModule = mongoose.model( "Flight" , fliteSchema );

const bookingSchema = mongoose.Schema({
    user: { type: Schema.Types.ObjectId, ref: 'user' },
    flight: { type: Schema.Types.ObjectId, ref: 'flight' }
})

const bookingModule = mongoose.model("Booking" , bookingSchema );

module.exports = {connection , userModule , fliteModule ,bookingModule}