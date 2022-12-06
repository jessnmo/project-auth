import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import e from 'express';

const mongoUrl = process.env.MONGO_URL || 'mongodb://localhost/project-mongo';
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = Promise;

// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080;
const app = express();

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(express.json());

const UserSchema = new mongoose.Schema({
	username: {
		type: String,
		required: true,
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
	accessToken: {
		type: String,
		default: () => crypto.randomBytes(128).toString('hex'),
		//npm install crypto
	},
});

const User = mongoose.model('User', UserSchema);

app.post('/register', async (req, res) => {
	const { username, password } = req.body;
	//npm install bcrypt
	try {
		const salt = bcrypt.genSaltSync();
		if (password.length < 8) {
			res.status(400).json({
				success: false,
				response: 'Password must be 8 or more characters long',
			});
		} else {
			const newUser = await new User({
				username: username,
				password: bcrypt.hashSync(password, salt),
			}).save();
			res.status(201).json({
				success: true,
				response: {
					username: newUser.username,
					accessToken: newUser.accessToken,
					id: newUser._id,
				},
			});
		}
	} catch (err) {
		res.status(400).json({
			success: false,
			response: err.errors,
		});
	}
});

app.post('/login', async (req, res) => {
	const { username, password } = req.body;

	try {
		const user = await User.findOne({ username });
		if (user && bcrypt.compareSync(password, user.password)) {
			res.status(200).json({
				success: true,
				response: {
					username: user.username,
					id: user._id,
					accessToken: user.accessToken,
				},
			});
		} else {
			res.status(400).json({
				success: false,
				response: "Credential didn't match",
			});
		}
	} catch (err) {
		res.status(500).json({
			success: false,
			response: err.errors,
		});
	}
});

const authenticateUser = async (req, req, next) => {
	const accessToken = req.header('Authorization');
	try {
		const user = await User.findOne({ accessToken: accessToken });
		if (user) {
			next();
		} else {
			res.status(401).json({
				success: false,
				response: 'Please log in',
			});
		}
	} catch (err) {
		res.status(400).json({
			success: false,
			response: err.errors,
		});
	}
};

// Start defining your routes here
app.get('/', (req, res) => {
	res.send('Hello Technigo!');
});

// Start the server
app.listen(port, () => {
	console.log(`Server running on http://localhost:${port}`);
});
