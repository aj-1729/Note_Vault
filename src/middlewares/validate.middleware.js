import ApiError from "../utils/Apierror.js";


const validate = (schema) => {
    async (req, res, next) => {
        try {
            const validatedResult = await schema.parseAsync({
                body: req.body
            });

            req.body = validatedResult.body;
            next();
        } catch (err) {

            const errorMessage = err.errors[0]?.message || "Validation Error";
            next(new ApiError(400, errorMessage));
        }

    }
};


export { validate };