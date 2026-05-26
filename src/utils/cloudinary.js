import {v2 as cloudinary} from 'cloudinary';

import fs from 'fs';

cloudinary.config({ 

    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET 

});


const uploadToCloudinary = async (noteContent)=>
{
    try {
        if(!noteContent) return null;

        const conContent = Buffer.from(noteContent).toString('base64');
        const dataURI = `data:text/plain;base64,${base64Content}`;

        const response = await cloudinary.uploader.upload(dataURI,{
            resource_type:"auto",
            folder: "Note_Vault"
        });

        return response.secure_url;
    } catch (error) {
        console.error("Cloudinary upload failed:", error);
        throw new ApiError(500, "Failed to upload note to secure storage");
    }
}

export{uploadToCloudinary}