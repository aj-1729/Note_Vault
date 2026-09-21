// Load environment variables before executing worker
import "dotenv/config";
import "./src/queues/emailWorker.js";

console.log("Worker process started successfully!");