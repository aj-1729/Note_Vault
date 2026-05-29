import express from "express";
import cors from "cors";
import cookieParser  from "cookie-parser";



const app = express();


app.use(cors({
    origin: process.env.NODE_ENV === "production"
        ? "https://notevault-api.onrender.com"
        : "http://localhost:8000",
    credentials: true
}));
app.use(cookieParser());
app.use(express.json({limit: "16kb"}));
app.use(express.urlencoded({extended: true, limit: "16kb"}));
app.use(express.static("public"));

import userRoutes from "./src/routes/users.routes.js"
import noteRoutes from "./src/routes/notes.routes.js"

app.use("/api/v1/users", userRoutes)
app.use("/api/v1/notes", noteRoutes)


export {app}

