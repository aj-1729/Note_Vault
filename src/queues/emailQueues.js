import { Queue } from 'bullmq';
import IORedis from 'ioredis';

const connection = new IORedis();

export const emailQueue = new Queue('emailQueue', { connection });


export const addEmailToQueue = async (emailData) => {
    await emailQueue.add("send-verification-email",
        emailData,
        {
            attempts: 3,
            backoff: { type: "exponential", delay: 1000 }
        }
    );
};

