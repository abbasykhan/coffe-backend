import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";
import Jwt from "jsonwebtoken";

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    avatar: {
      type: String, //cloudinary url
      required: true,
    },
    coverImage: {
      type: String, //cloudinary url
    },
    watchHistroy: [
      {
        type: Schema.Types.ObjectId,
        ref: "Video",
      },
    ],
    password: {
      type: String,
      required: [true, "password is required"],
    },
    refreshToken: {
      type: String,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  //jwt is bearer token, is like a key , when user have this , it can access data easily
 try {
   return Jwt.sign(
     {
       _id: this._id,
       _email: this._email,
       username: this.username,
       fullName: this.fullName,
     },
     process.env.ACCESS_TOKEN_SECRET,
     {
       expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
     }
   );
 } catch (error) {
  console.error("Error generating access token:", error);
  
 }
};
userSchema.methods.generateRefreshToken = function () {
 try {
   return Jwt.sign(
     {
       _id: this._id,
     },
     process.env.REFRESH_TOKEN_SECRET,
     {
       expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
     }
   );
 } catch (error) {
   console.error("Error generating access token:", error);
 }
};

export const User = mongoose.model("User", userSchema);
