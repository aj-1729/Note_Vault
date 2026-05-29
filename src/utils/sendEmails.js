import { Resend } from "resend";

import dotenv from "dotenv";
dotenv.config();



const resend = new Resend(process.env.RESEND_API_KEY);


export const sendEmail = async ({ email, subject, html }) => {
    try {
        const data = await resend.emails.send({
            from: 'Note Vault <onboarding@resend.dev>',
            to: email, 
            subject: subject,
            html: html,
        });

        return data;
    } catch (error) {
        console.error("Resend Email Error:", error);
        throw new Error("Failed to send verification email");
    }
};