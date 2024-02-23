import {asyncHandler} from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"


const registerUser = asyncHandler( async (req, res) => {
    //get user details from frontend
    //validationn ( see it is empty or not)
    // check if user is  already registered or not
    //check for images, check for avtar for this project
    //upload them to cloudinary
    //creat user object - create entry in db
    //remove password and refresh token field from response
    //check for user creation
    // return response 

    const {fullName, email, username, password} = req.body
    console.log("email: ", email)

    if (
        [fullName, email, username, password].some((field) =>
        field?.trim()==="")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = User.findOne({
        $or:[{ username }, { email }]
    })

    if (existedUser){
        throw new ApiError(409, "Email or Username has already been used")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    const coverImageLocalPath = req.files?.coverImage[0]?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar= await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage:  coverImage?.url || "",
        email,
        username: username.toLowerCase,
        password
    })

    const createdUser= await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if (!createdUser) {
        throw new ApiError(500, "Failed to create a user")
    }


    return res.status(201).json(
        new ApiResponse(200, createdUser, "Successfully signed up!")
    )

})


export {
    registerUser,
}