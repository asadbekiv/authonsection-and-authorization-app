import jwt from "jsonwebtoken";
import  User  from "../models/user.js";

export const CreateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.EXPIRES_IN,
  });
};
