const express = require('express');
const Mongoose = require("mongoose");
const { Donor } = require("./models/donermodels");
const { User } = require("./models/donermodels");
const { Request } = require("./models/donermodels");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const uuid = require("uuid");
const authorization = require('./middleware/authorize');

const app = express();
app.use(express.json());
app.use(cors());

const port = 5001;
//TODO: wXYDFX5fQhRoKQc5

Mongoose.connect("mongodb+srv://rafatmaita:wXYDFX5fQhRoKQc5@myfirstnodejscluster.zcjq63q.mongodb.net/?retryWrites=true&w=majority")
    .then(() => {
        console.log("Rafat you are a hero");
    }).catch(() => {
        console.log("Error With connect To The DataBase");
    });

const generateUserId = () => {
    return uuid.v4();
};



//TODO:Donor  
//! signup to the  --->
//?Donor 
app.post("/signup", async (req, res) => {
    try {
        console.log(req.body);
        const { userName, emailAddress, password } = req.body;

        // Validate the request body using Joi
        const schema = Joi.object({
            userName: Joi.string().required(),
            emailAddress: Joi.string().email().required(),
            password: Joi.string().required(),
        });

        const { error } = schema.validate({ userName, emailAddress, password });
        if (error) {
            return res.status(400).json({ message: "Validation error", error: error.details });
        }

        // Check if the user already exists
        const existingUser = await Donor.findOne({ emailAddress });
        if (existingUser) {
            return res.status(400).send("User already exists");
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create a new Donor instance and save it to the database
        const newDonor = new Donor({
            userName,
            emailAddress,
            password: hashedPassword,
        });

        const savedUser = await newDonor.save();
        res.status(200).json(savedUser);
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message });
    }
});


//TODO:Donor 
//! login to the  --->
//?Donor
app.post("/login", async (req, res) => {
    const schema = Joi.object({
        emailAddress: Joi.string().email().required(),
        password: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await Donor.findOne({ emailAddress: req.body.emailAddress });
    if (!user) return res.status(400).send("User not found");

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send("Invalid password");

    const token = jwt.sign({ _id: user._id }, "your-secret-key", { expiresIn: "10h" });
    res.cookie("accessToken", token, { httpOnly: true });
    res.json({ userId: user._id, authToken: token });

});
//TODO:user 
//! signup to users --->
//?users

app.post('/signup/users', async (req, res) => {
    const { type, username, emailAddress, password } = req.body;

    // Validate the input using Joi
    const schema = Joi.object({
        type: Joi.string().valid('School', 'University', 'Institution', 'Park').required(),
        username: Joi.string().required(),
        emailAddress: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
    });

    const { error } = schema.validate({ type, username, emailAddress, password });
    if (error) {
        return res.status(400).json({ message: 'Validation error', error: error.details });
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ emailAddress });
        if (existingUser) {
            return res.status(400).send('User already exists');
        }

        // Hash the password before saving to the database
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create a new user instance
        const newUser = new User({
            type,
            username,
            emailAddress,
            password: hashedPassword,
        });

        // Save the user to the database
        const savedUser = await newUser.save();

        // Respond with the user's ID
        res.send({ user: savedUser._id });
    } catch (error) {
        res.status(400).send(error.message);
    }
});


//TODO:USER 
//! login to the user --->
//?user
app.post('/login/users', async (req, res) => {
    const schema = Joi.object({
        emailAddress: Joi.string().email().required(),
        password: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    try {
        // Find the user by email address
        const user = await User.findOne({ emailAddress: req.body.emailAddress });
        if (!user) {
            return res.status(400).send('User not found');
        }

        // Compare the provided password with the stored hashed password
        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(400).send('Invalid password');
        }

        // Generate a JWT token
        const token = jwt.sign({ _id: user._id }, 'your-secret-key', { expiresIn: '10h' });

        // Set the token as a cookie (optional)
        res.cookie('accessToken', token, { httpOnly: true });

        // Respond with the user's ID and authentication token
        res.json({ userId: user._id, authToken: token });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});


//TODO:USER 
//! add request to the  --->
//?user

app.post('/addRequest', authorization.authorize, async (req, res) => {
    try {
        const { address, description, dueDate } = req.body;

        // Create a new request using the Request model
        const newRequest = new Request({
            user: req.user._id, // Assuming the user ID is stored in the JWT payload
            address,
            description,
            dueDate,
        });

        // Save the request to the database
        const savedRequest = await newRequest.save();

        res.status(201).json(savedRequest);
    } catch (error) {
        console.log(error);
        res.status(500).json(error);
    }
});

//TODO:user
//! edit request for the  --->
//?User

app.put('/editRequest/:id', authorization.authorize, async (req, res) => {
    try {
        const { address, description, dueDate } = req.body;

        // Check if the request ID is valid
        if (!req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ message: 'Invalid request ID' });
        }

        // Find the request by ID and user ID
        const existingRequest = await Request.findOne({
            _id: req.params.id,
            user: req.user._id,
        });

        if (!existingRequest) {
            return res.status(404).json({ message: 'Request not found' });
        }

        // Update the request fields
        existingRequest.address = address || existingRequest.address;
        existingRequest.description = description || existingRequest.description;
        existingRequest.dueDate = dueDate || existingRequest.dueDate;

        // Save the updated request to the database
        const updatedRequest = await existingRequest.save();

        res.status(200).json(updatedRequest);
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error', error: error.message });
    }
});


//TODO:user 
//! get all request for --->
//?user
app.get('/getRequestUser', authorization.authorize, async (req, res) => {
    try {
        const userId = req.user._id;

        // Find requests by user ID
        const requests = await Request.find({ user: userId });

        res.status(200).json(requests);
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error', error: error.message });
    }
});







const GoogleStrategy = require('passport-google-oauth2').Strategy;
app.use(express.json());
const passport = require('passport');
const session = require('express-session');
app.use(session({ secret: 'process.env.SECRET_KEY', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());



//TODO:Donor 
//! Login with google for  --->
//?Donor 
app.get('/auth/google',
    passport.authenticate('google',
        {
            scope:
                ['email', 'profile']
        }
    ));




//TODO:Donor 
//! After login he is call this routes --->
//?Donor
app.get('/google/callback',
    passport.authenticate('google', {
        successRedirect: '/protected',
        failureRedirect: '/not',
    }));




//TODO:Donor  
//! get all form google  for --->
//?Donor
app.get('/protected', authorization.authorize, (req, res) => {
    res.send(req.user);
})



//!Handell for login the google 
passport.use(new GoogleStrategy({
    clientID: '567380053461-ikskjhvv483ccu7k6d3lrr659hse9737.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'http://localhost:5001/google/callback',
    passReqToCallback: true,
}, async (req, accessToken, refreshToken, profile, done) => {
    try {
        if (req.isAuthenticated()) {
            done(null, req.user);
        }

        const existingUser = await Donor.findOne({
            $or: [
                { googleID: profile.id },
                { emailAddress: profile.email },
            ],
        });

        if (existingUser) {
            done(null, existingUser.toJSON());
        } else {
            const newUser = new Donor({
                userName: profile.displayName,
                emailAddress: profile.email,
                profile_img: profile.picture,
                user_location: profile._json && profile._json.location || null,
                googleID: profile.id,
            });

            const savedUser = await newUser.save();
            done(null, savedUser.toJSON());
        }
    } catch (error) {
        done(error);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser(async (user, done) => {
    done(null, user);
});



//TODO:Admin 
//! get all request for --->
//?ADMIN
app.get('/getRequests', async (req, res) => {
    try {
        const requests = await Request.find().populate({
            path: 'user',
            select: 'type username',
        });

        res.json(requests);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});







app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
