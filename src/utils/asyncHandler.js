const asyncHandler = (fn) => async (req, res, next) => {
    try{
        await fn(req, res, next)
    }
    catch (error) {
        const statusCode = (error.statusCode && error.statusCode < 1000) ? error.statusCode : 400;
        res.status(statusCode).json({
            success: false,
            message: error.message || "Internal Server Error"
        });
    }
}

export  {asyncHandler};