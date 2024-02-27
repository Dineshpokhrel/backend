import {asyncHandler} from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from  "jsonwebtoken"


const generateAccessAndRefreshTokens = async(userId) =>
{
    try {
        const user= await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave:false  })  // To bypass the validation of token fields while saving to DB

        return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
}

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
    //onsole.log("email: ", email)

    if (
        [fullName, email, username, password].some((field) =>
        field?.trim()==="")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or:[{ username }, { email }]
    })

    if (existedUser){
        throw new ApiError(409, "Email or Username has already been used")
    }
    //console.log(req.files)

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0 ){
        coverImageLocalPath = req.files.coverImage[0].path
    }

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
        username,
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

const loginUser = asyncHandler(async(req,res) => {
    // req body -> take data
    // username or email 
    // find the user
    // check password
    // access and refresh token
    // send cookie
    const {email, username, password} = req.body
    if (!( username || email)) {
        throw new ApiError(400, "Username or email is required")
    }
    const user = await User.findOne({
        $or:[{username},{email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }
    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .cookie("accessToken", accessToken ,options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Sucessfully"
        )
    )
})


const logoutUser = asyncHandler(async(req, res) =>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set :{
                refreshToken: undefined
            }
        },
        {
            new:true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json( new ApiResponse(200, {}, "User logged out"))
})


const refreshAccessToken = asyncHandler(async (req,res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, 'Unauthorized request')
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken, 
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
        }
    
       
        const options = {
            httpOnly: true,
            secure: true
        }
        //Generate a new access token
        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(400, error?.message || "Invalid refresh token")
    }
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken
}