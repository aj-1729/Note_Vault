import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

console.log("EMAIL_USER:", process.env.EMAIL_USER);
console.log(
    "EMAIL_APP_PASSWORD:",
    process.env.EMAIL_APP_PASSWORD ? "SET" : "NOT SET"
);

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD,
    },
});

export const sendEmail = async ({ email, subject, html }) => {
    try {
        console.log("📧 Attempting to send email to:", email);

        await transporter.verify();

        console.log(" Gmail SMTP connection successful");

        const info = await transporter.sendMail({
            from: `Note Vault <${process.env.EMAIL_USER}>`,
            to: email,
            subject,
            html,
        });

        console.log(" EMAIL SENT:", info.messageId);

        return info;
    } catch (error) {
        console.error(" EMAIL FAILED:");
        console.error(error);

        throw error;
    }
};