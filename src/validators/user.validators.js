import { z } from "zod";


const registerSchema = z.object({
    body: z.object(
        {
            username: z.string({ required_error: "Username is required" })
                .trim()
                .min(3, "Username must be at least 3 characters"),


            email: z.string({ required_error: "email is required" })
                .email("Invalid email address format"),


            password: z.string({ required_error: "Password is required" })
                .min(6, "Password must be atleast 6 characters long")
        }
    )
});


export { registerSchema }