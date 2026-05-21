import express from "express";
import cors from "cors";
import cookieParser  from "cookie-parser";



const app = express();


app.use(cors());
app.use(cookieParser());
app.use(express.json({limit: "16kb"}));
app.use(express.urlencoded({extended: true, limit: "16kb"}));
app.use(express.static("public"));

import userRoutes from "./src/routes/users.routes.js"

app.use("/api/v1/users", userRoutes)


export {app}

