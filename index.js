const express = require('express');
const app = express();
app.use(express.json());
require('dotenv').config(); 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const {connection , userModule , fliteModule ,bookingModule} = require('./db')
const cookie = require('cookie');
const cookieParser = require('cookie-parser');
app.use(cookieParser())




const protectRoute = async(req , res, next)=>{
    try {
        const token = req.cookies.token;
        if(!token){
            return res.status(401).send({error : "not Authorized  "})
        }
        const decoded = jwt.verify(token , process.env.Key);
        if(!decoded){
            return res.status(401).send({error : "not Authorized"})
        }
        const user = await userModule.findById(decoded.userId).select("-password");
        if(!user){
            return res.status(404).send({error : "User not found here"});
        }
        req.user = user;
        next();
    } catch (error) {
        console.log("Error from protect middleware   " , error)
        res.status(500).send(error.message)
    }
}





app.post("/api/register" , async(req , res)=>{
    const {name  , email , password} = req.body;
    try {
    if(!name || !email || !password){
        res.send('All filled required')
    }
    const avil = await userModule.find({email:email});
    if(avil.length !== 0){
        res.send('Email Already Exist')
    }else{
    const hash = bcrypt.hash(password , 6 , async function(err , hash){
        if(err){
            console.log(err)
        }else{
            await userModule.create({name:name , email:email , password: hash });
            res.status(201).send({name:name , email:email , password: password });
            console.log('user created');
        }
    })
}
} catch (error) {
    console.log('error from post user function' , error);
}
})


app.post("/api/login" , async(req , res)=>{
    const {email , password} = req.body;
    const user = await userModule.findOne({email:email});
    console.log(user)
    const hashed = user.password;
    try {
         bcrypt.compare(password , hashed , function(err , result){
            if(result == true){
                console.log(result);
                const token = jwt.sign({userId : user._id} , process.env.Key);
                res.cookie('token' ,token , {
                    maxAge : 15 * 24 * 60 * 60 * 1000, 
                    httpOnly : true ,
                    sameSite:"strict",
                    secure : process.env.NODE_ENV !== "development" 
                });
                res.status(201).send({message :'User Found' , token:token})
            }else{
                res.status(404).send(err + "user not found")
            }
        })
    } catch (error) {
        console.log('Error From login function   :'+error)
    }
})

app.get("/api/flights" , async(req , res)=>{
    try {
        const flites = await fliteModule.find();
        res.status(200).send(flites)
    } catch (error) {
        console.log("Error From get flites Function  :   "+error)
    }
})



app.get("/" , async(req , res)=>{
    try {
        const flites = await fliteModule.find();
        res.status(200).send(flites)
    } catch (error) {
        console.log("Error From get flites Function  :   "+error)
    }
})


app.get("/api/flights/:id" , async(req , res)=>{
    const id = req.params.id;
    try {
        const flites = await fliteModule.findById(id);
        res.status(200).send(flites);
    } catch (error) {
        console.log("Error From get flites Function  :   "+error)
    }
})


app.get("/api/dashboard" , protectRoute ,async(req , res)=>{
    try {
        const flites = await bookingModule.find();
        res.status(200).send(flites);
    } catch (error) {
        console.log("Error From get flites Function  :   "+error)
    }
})




app.post("/api/flights" , protectRoute , async(req , res)=>{
    const {airline, flightNo, departure, arrival, departureTime, arrivalTime, seats, price} = req.body;
try {
    await fliteModule.create({airline, flightNo, departure, arrival, departureTime, arrivalTime, seats, price});
    res.status(201).send("data posted");
} catch (error) {
    console.log('this error from flights post  :'+error)
}
})

app.post("/api/booking", protectRoute, async (req, res) => {
    const user = req.user;
    const flight_id = req.query.id;
    console.log(flight_id);

    const userData = await userModule.findById(user._id);
    const flightData = await fliteModule.findById(flight_id)
    console.log(userData);
    console.log(flightData)
    try {
        // const data = { user: user._id, flight: flight_id };
        await bookingModule.create({user : userData , flight: flightData});
        res.status(201).send({ user: userData, flight: flightData });
    } catch (error) {
        console.log('Error from booking post:', error);
        res.status(500).send(error.message);
    }
});





app.put("/api/booking", protectRoute, async (req, res) => {
    try {
        const id = req.query.id; 
        const data = req.body;
        console.log(id) 
        const update = await fliteModule.findById(id);
        if (!update) {
            return res.status(404).send("Flight not found.");
        }

        update.flight = data.flight || update.flight;
       
        const updatedFlight = await update.save();
        console.log(updatedFlight)
        res.status(200).send("data updated");
    } catch (error) {
        res.status(500).send(error.message);
        console.log('Error from flight update:', error);
    }
});