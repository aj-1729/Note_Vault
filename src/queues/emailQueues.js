import { Queue } from 'bullmq';
import { getBullMQConnection } from '../db/redis.js';

export const EMAIL_QUEUE_NAME = "emailQueue";

export const emailQueue = new Queue(EMAIL_QUEUE_NAME, {
    connection: getBullMQConnection()
});

emailQueue.on("error", (error) => {
    console.error("BullMQ emailQueue error:", error);
});

export const addEmailToQueue = async (emailData) => {
    await emailQueue.add(
        "send-verification-email",
        emailData,
        {
            attempts: 3,
            backoff: { type: "exponential", delay: 1000 }
        }
    );
};


