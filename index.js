
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        // Not logged in — show Sign Up and Log In buttons
        res.send(`
            <h1>Welcome to the Site!</h1>
            <a href="/signup"><button>Sign Up</button></a>
            <a href="/login"><button>Log In</button></a>
        `);
    } else {
        // Logged in — show greeting and Members + Logout buttons
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href="/members"><button>Go to Members Area</button></a>
            <a href="/logout"><button>Log Out</button></a>
        `);
    }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});






app.get('/signup', (req,res) => {
    var html = `
    Sign Up
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='Full Name'>
    <input name='email' type='text' placeholder='Email'>
    <input name='password' type='password' placeholder='Password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!name || !email || !password) {
        res.send("Missing field(s). Please go back and fill all fields.");
        return;
    }

    const schema = Joi.object({
        name: Joi.string().max(30).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(30).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("Invalid input. Please try again.");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name, email, password: hashedPassword });
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

/*app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        res.send("Invalid input.");
        return;
    }

    /*const result = await userCollection.find({ email }).toArray();
    if (result.length != 1) {
        res.send("Email not found.");
        return;
    }
        
    console.log("Trying to log in with email:", email);

    const result = await userCollection.find({ email }).toArray();
    console.log("MongoDB result:", result);
        

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;
        res.redirect("/members");
    } else {
        res.send("Incorrect password. <a href='/login'>Try again</a>");
    }
});*/

app.post('/loggingin', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error) {
        console.log("Validation error:", validationResult.error);
        return res.send(`
            <h3>Invalid input. Please enter a valid email and password.</h3>
            <a href="/login">Back to Login</a>
        `);
    }

    try {
        const user = await userCollection.findOne({ email: email });

        if (!user) {
            console.log("User not found for email:", email);
            return res.send(`
                <h3>Email not found. Please try again.</h3>
                <a href="/login">Back to Login</a>
            `);
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            console.log("Incorrect password for email:", email);
            return res.send(`
                <h3>Incorrect password. Please try again.</h3>
                <a href="/login">Back to Login</a>
            `);
        }

        // Successful login
        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.cookie.maxAge = expireTime;

        console.log("User logged in:", user.email);
        res.redirect("/members");

    } catch (err) {
        console.error("Error during login:", err);
        res.send("An error occurred. Please try again later.");
    }
});



app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/');
    }

    const images = ["/image1.jpg", "/image2.jpg", "/image3.jpg"];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.name}</h1>
        <img src="${randomImage}" style="width:300px;">
        <br><a href="/logout">Logout</a>
    `);
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 