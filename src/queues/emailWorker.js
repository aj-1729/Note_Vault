import { Worker } from 'bullmq';
import IORedis from 'ioredis';
import { sendEmail } from '../utils/sendEmails.js';

const connection = new IORedis({
    maxRetriesPerRequest: null
});


export const emailWorker = new Worker("email-queue", async (job) => {
    console.log("Processing email job");

    await sendEmail(
        {
            email: job.data.email,
            subject: job.data.subject,
            html: job.data.html

        }
    )
}, { connection })



