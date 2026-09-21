import { Worker } from 'bullmq';
import { sendEmail } from '../utils/sendEmails.js';
import { getBullMQConnection } from '../db/redis.js';
import { EMAIL_QUEUE_NAME } from './emailQueues.js';

export const emailWorker = new Worker(
    EMAIL_QUEUE_NAME,
    async (job) => {
        console.log(`Processing email job: ${job.id}`);

        await sendEmail({
            email: job.data.email,
            subject: job.data.subject,
            html: job.data.html
        });
    },
    { connection: getBullMQConnection() }
);

emailWorker.on("completed", (job) => {
    console.log(`Email job ${job.id} completed successfully`);
});

emailWorker.on("failed", (job, err) => {
    console.error(`Email job ${job?.id} failed with error:`, err);
});

emailWorker.on("error", (err) => {
    console.error("BullMQ Worker error:", err);
});
