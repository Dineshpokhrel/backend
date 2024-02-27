import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"


export const verifyJWT = asyncHandler(async(req, _, next) =>{ // here we use _  as a placeholder for the res parameter
try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");  //get the token from cookies or header
    
        if (!token) {
            throw new ApiError(401, "Unauthorized request")
        }
    
        const decodedTokenInformation = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    
        const user= await User.findById(decodedTokenInformation?._id)
        .select("-password -refreshToken")  
    
        if (!user) {
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user = user
        next()
} catch (error) {
    throw new ApiError(401, error?.message || "Invalid access token")
}

})