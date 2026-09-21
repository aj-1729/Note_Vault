import nodemailer from "nodemailer";
import dotenv from "dotenv";


dotenv.config();


const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD,
    },
});


export const sendEmail = async ({ email, subject, html }) => {
    try {
        const info = await transporter.sendMail({
            from: `Note Vault <${process.env.EMAIL_USER}>`,
            to: email,
            subject: subject,
            html: html,
        });

        console.log("Email sent successfully:", info.messageId);

        return info;
    } catch (error) {
        console.error("Gmail Email Error:", error);
        throw new Error("Failed to send verification email");
    }
};