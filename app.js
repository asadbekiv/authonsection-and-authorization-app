import express from "express";
import bodyParser from "body-parser";
import router from "./routes/userRoute.js";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";
import { dirname } from "path";
const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

app.use(bodyParser.json()); //1
app.use(cookieParser()); //2

app.use("/auth", router); //3

// console.log(__dirname);

app.get("/welcome", (req, res) => {
  res.send("<h1>Welcome Express Authcheck Project !</h1>");
});

export default app;
