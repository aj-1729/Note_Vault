import Redis from "ioredis";
import dotenv from "dotenv";

dotenv.config();

const defaultRedisOptions = {
    host: process.env.REDIS_HOST || "127.0.0.1",
    port: Number(process.env.REDIS_PORT) || 6379,
    maxRetriesPerRequest: null,
};

// General-purpose Redis client for caching (used in notes controller, etc.)
export const redis = process.env.REDIS_URL
    ? new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: null })
    : new Redis(defaultRedisOptions);

redis.on("connect", () => {
    console.log("Connected to Redis");
});

redis.on("error", (error) => {
    console.error("Error: Redis connection failed!!", error);
});

// Dedicated connection factory for BullMQ Queue and Worker instances
export const getBullMQConnection = () => {
    if (process.env.REDIS_URL) {
        return new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: null });
    }
    return new Redis(defaultRedisOptions);
};
