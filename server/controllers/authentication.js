const jwt = require("jwt-simple");
const User = require("../models/user");
const dotenv = require("dotenv").config();

const tokenForUser = user => {
	const timestamp = new Date().getTime();
	return jwt.encode({ sub: user.id, iat: timestamp }, process.env.secret);
};

exports.signup = (req, res, next) => {
	const { email, password } = req.body;

	if (!email || !password) {
		return res
			.status(422)
			.send({ error: "You must provide email and password" });
	}

	// Check for user with given email
	User.findOne({ email: req.body.email }, (err, existingUser) => {
		if (err) {
			return next(err);
		}
		// If user exists, throw error
		if (existingUser) {
			return res.status(422).send({ error: "Email is in use" });
		}

		const user = new User({
			email,
			password
		});

		user.save(err => {
			if (err) {
				return next(err);
			}
		});

		res.json({ token: tokenForUser(user) });
	});
};

exports.signin = (req, res, next) => {
	// Supply token to authenticated user
	res.send({ token: tokenForUser(req.user) });
};
