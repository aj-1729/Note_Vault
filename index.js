import dotenv from "dotenv";
import mongoose from "mongoose";
import { DB_NAME } from "./constants.js";
import { connectDB } from "./src/db/index.js";
import { app } from "./app.js";
import http from "http";
import { Server } from "socket.io";

dotenv.config({ path: "./.env" })
const server = http.createServer(app);

export const io = new Server(server, {
    cors: { origin: "*" }
});

io.on("connection", (socket) => {
    console.log("A user connected via WebSocket!");

    // Put the user in a private "room" based on their ID so they only sync their own notes
    socket.on("join_vault", (userId) => {
        socket.join(userId);
        console.log(`User securely joined vault room: ${userId}`);
    });
});
connectDB().then(
    () => {
        server.listen(process.env.PORT || 5000, () => {
            console.log(`App is listening on port ${process.env.PORT || 5000}`);
        })
    }
)

    .catch((error) => {
        console.log("Error: MongoDB connect failed!!", error);
    })