
import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import app from "./app.js";


const DB = process.env.MONGODB_URL;
mongoose
  .connect(DB, {
    serverSelectionTimeoutMS: 5000,
  })
  .then(() => {
    console.log("DB connected successfuly");
  })
  .catch((err) => console.log(err.reason));

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
