import dotenv from "dotenv";
import mongoose  from "mongoose";
import { DB_NAME } from "./constants.js";
import { connectDB } from "./src/db";
import { app } from "./app.js";

dotenv.config({path: "./.env"})

connectDB.then(
    ()=>
    {
        app.listen(process.env.PORT || 5000, () =>
        {
            console.log("App is listening on port ${process.env.PORT || 5000}");
        })
    }
)

.catch((error) =>
{
    console.log("Error: MongoDB connect failed!!", error);
})