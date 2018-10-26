const mongoose = require("mongoose");
const bcrypt = require("bcrypt-nodejs");

const userSchema = new mongoose.Schema({
	email: {
		type: String,
		unique: true,
		required: true,
		lowercase: true
	},
	password: {
		type: String,
		required: true
	}
});

// Encrypt password before saving user
userSchema.pre("save", function(next) {
	const user = this;

	// Generate salt
	bcrypt.genSalt(10, (err, salt) => {
		if (err) {
			return next(err);
		}
		// Hash password using salt
		bcrypt.hash(user.password, salt, null, (err, hash) => {
			if (err) {
				return next(err);
			}

			user.password = hash;
			next();
		});
	});
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
	bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
		if (err) {
			return cb(err);
		}

		cb(null, isMatch);
	});
};

module.exports = mongoose.model("user", userSchema);
