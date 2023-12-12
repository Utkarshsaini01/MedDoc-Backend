require('dotenv').config();

// app.js
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const admin = require("firebase-admin");
const cors = require("cors");
// const { Storage } = require('@google-cloud/storage');

const PORT = process.env.PORT || 5000;

const app = express();
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const serviceAccount = require(process.env.serviceAccountKeyPath);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.storageBucket,
});

const bucket = admin.storage().bucket();

// Secret key for signing and verifying JWTs (keep this secret!)
const mySecretKey = process.env.secretKey;

// Connect to MongoDB (replace 'your-database-name' and 'your-mongodb-uri' with your actual database information)
const mongoURI = "mongodb+srv://sainiutkarsh01:"+process.env.db+".mongodb.net/TARP";

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });

 

// Create a user schema and model
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  dob: Date,
  gender: String,
});

const User = mongoose.model("User", userSchema);

const doctorSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  dob: Date,
  gender: String,
});

const Doctor = mongoose.model("Doctor", doctorSchema);

const FileSchema = new mongoose.Schema({
  filename: String,
  url: String,
  user_id: mongoose.Schema.Types.ObjectId,
});

const File = mongoose.model("File", FileSchema);


const sharingSchema = new mongoose.Schema({
  fileId: String, // ID of the shared document
  userId: String,     // ID of the user sharing the document
  doctorId: String,   // ID of the doctor who can access the document
});

const Sharing = mongoose.model('Sharing', sharingSchema);


const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  let token = req.headers.authorization;
  token = token.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: Token is missing" });
  }

  // Verify and decode the token
  jwt.verify(token, mySecretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
    req.userId = decoded.userId; // Make the user ID available to the request
    next();
  });
}

// Endpoint for user signup
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, dob, gender, userType } = req.body;

    if (userType === "user") {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "Email already in use" });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user
      const newUser = new User({
        username,
        email,
        password: hashedPassword,
        dob,
        gender,
      });
      await newUser.save();

      res.status(201).json({ message: "Signup successful" });
    } else {
      // Check if the email is already in use
      const existingDoctor = await Doctor.findOne({ email });
      if (existingDoctor) {
        return res.status(400).json({ message: "Email already in use" });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user
      const newDoctor = new Doctor({
        username,
        email,
        password: hashedPassword,
        dob,
        gender,
      });
      await newDoctor.save();

      res.status(201).json({ message: "Signup successful" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Endpoint for user login
app.post("/login", async (req, res) => {
  try {
    const { email, password, loginAs } = req.body;

    // Find the user by email
    if (loginAs === "patient") {
      const foundUser = await User.findOne({ email });

      if (!foundUser) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Compare the provided password with the hashed password
      const passwordMatch = await bcrypt.compare(password, foundUser.password);

      if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Generate a JWT token
      // console.log(foundUser.id);
      const token = jwt.sign({ userId: foundUser.id }, mySecretKey, {
        expiresIn: "1h",
      });

      res.status(200).json({ message: "Login successful", token });
    } else {
      const foundUser = await Doctor.findOne({ email });

      if (!foundUser) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Compare the provided password with the hashed password
      const passwordMatch = await bcrypt.compare(password, foundUser.password);

      if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Generate a JWT token
      // console.log(foundUser.id);
      const token = jwt.sign({ userId: foundUser.id }, mySecretKey, {
        expiresIn: "1h",
      });

      res.status(200).json({ message: "Login successful", token });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Define a route for file upload
app.post("/upload", verifyToken, upload.single("pdf"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded." });
    }
    const filename = req.body.filename;
    const file = req.file;
    const uniqueFileName = Date.now() + "_" + file.originalname;

    // Upload the file to Firebase Storage
    const blob = bucket.file(uniqueFileName);
    const blobStream = blob.createWriteStream();

    blobStream.on("error", (err) => {
      console.error(err);
      return res
        .status(500)
        .json({ error: "Error uploading file to Firebase." });
    });

    blobStream.on("finish", async () => {
      // Get the file's URL from Firebase Storage

      const config = {
        action: "read",
        // A timestamp when this link will expire
        expires: "01-01-2026",
      };

      

      blob.getSignedUrl(config, async function (err, result) {
        if (err) {
          console.log(err);
          return;
        } else {
          const url = result;
          // Save the file's URL to MongoDB
          const savedFile = new File({
            filename: filename,
            url: url,
            user_id: req.userId,
          });

          await savedFile.save();

          return res
            .status(200)
            .json({ message: "File uploaded successfully."});
        }
      });
      
    });

    blobStream.end(file.buffer);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/files/:id", async (req, res) => {
  try {
    const fileId = req.params.id;

    // Retrieve the URL from MongoDB based on the fileId
    const file = await File.findOne({ _id: fileId });

    if (!file) {
      return res.status(404).json({ error: "File not found." });
    }

    // Redirect the user to the Firebase Storage URL
    return res.redirect(file.url);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// Define a GET endpoint to retrieve all user's files
app.get('/files', verifyToken, async (req, res) => {
  try {
    // Replace 'userId' with your actual user ID retrieval logic.
    const userId = req.userId;
    // console.log(userId);

    // Retrieve all files associated with the user from MongoDB
    const userFiles = await File.find({ user_id : userId }); // Assuming your File model has a userId field.

    // If no files are found, return an empty array or appropriate message
    if (!userFiles || userFiles.length === 0) {
      return res.status(404).json({ message: 'No files are uploaded' });
    }

    // Prepare the response with necessary file information
    const filesData = userFiles.map((file) => ({
      fileId: file._id, // Assuming you have an '_id' field for each file in MongoDB
      filename: file.filename,
      url: file.url,
      // Replace with the actual field name
    }));

    return res.status(200).json(filesData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});


app.post('/sharedoc', verifyToken, async (req, res) => {
  try{
    const userId = req.userId;
    const fileId = req.body.fileId;
    const email = req.body.email;

    const foundDoctor = await Doctor.findOne({ email : email });

    if(!foundDoctor){
      return res.status(401).json({ message: "Doctor not exist" });
    }

    const newShare = new Sharing({
      userId : userId,
      fileId : fileId,
      doctorId : foundDoctor.id,
    });
    await newShare.save(); 
   
    return res.status(200).json({message: "Doctor added"});
  } catch (error){
    res.status(500).json({message : 'Internal server error'});
  }
});



app.get('/doctoraccess', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const fileId = req.query.fileId;

    // Find all sharing records that match the userId and fileId
    const sharingInfoList = await Sharing.find({ userId : userId, fileId : fileId });

    if (sharingInfoList.length === 0) {
      return res.status(404).json({ message: 'No matching sharing info found' });
    }

    // Create an array to store doctor details
    const doctorDetails = [];

    for (const sharingInfo of sharingInfoList) {
      // Use each doctorId to find doctor details in the Doctor model
      const doctorInfo = await Doctor.findOne({_id : sharingInfo.doctorId});

      if (doctorInfo) {
        doctorDetails.push({
          id : doctorInfo._id,
          name: doctorInfo.username,
          email: doctorInfo.email,
        });
      }
    }

    // Send the array of doctor details to the user
    res.status(200).json(doctorDetails);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.get('/getdocs', verifyToken, async(req, res) => {
  try {
    const doctorId = req.userId; // Assuming your middleware sets the doctorId in the request
    
    const sharingInfoList = await Sharing.find({ doctorId: doctorId });
    
    if (sharingInfoList.length === 0) {
      return res.status(404).json({ message: 'No matching sharing info found' });
    }

    const data = [];

    for (const sharingInfo of sharingInfoList) {
      const userId = sharingInfo.userId;
      
      const fileId = sharingInfo.fileId;
    
      try {
        const [user, file] = await Promise.all([
          User.findOne({ _id: userId }),
          File.findOne({ _id: fileId }),
        ]);
        
        

        if (user && file) {
          data.push({
            userName: user.username,
            userEmail: user.email,
            fileName: file.filename,
            fileUrl: file.url,
          });
        }
      } catch (error) {
        console.error(`Error while fetching user and file data: ${error}`);
      }
    }

    res.status(200).json(data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.delete('/files/:fileId', verifyToken, async (req, res) => {
  try {
    const userId = req.userId; // Assuming your middleware sets the doctorId in the request
    const fileId = req.params.fileId;

    // Check if the file with the given fileId belongs to the doctor (owner) before allowing deletion.
    const file = await File.findOne({ _id: fileId, user_id: userId });


    if (!file) {
      return res.status(404).json({ message: 'File not found or you do not have permission to delete it' });
    }

    // Check if there are sharing records associated with the file
    const sharingRecords = await Sharing.find({ fileId: fileId , userId: userId});

    if (sharingRecords && sharingRecords.length > 0) {
      // Delete sharing records associated with the file
      await Sharing.deleteMany({ fileId: fileId, userId: userId });
    }

    await File.deleteOne({ _id: fileId, user_id: userId });

    res.status(200).json({ message: 'File and associated sharing records deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/deletedoctor', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { fileId, doctorId } = req.body;

    // Verify that the requesting user has the appropriate permissions to delete the record.
    const sharingInfo = await Sharing.findOne({ userId, doctorId });

    if (!sharingInfo) {
      return res.status(404).json({ message: 'Sharing info not found' });
    }

    // Find and delete the record matching the provided userId and doctorId.
    const result = await Sharing.deleteOne({ userId: userId, doctorId: doctorId, fileId: fileId });

    if (result.deletedCount > 0) {
      return res.status(200).json({ message: 'Doctor record deleted successfully' });
    } else {
      return res.status(404).json({ message: 'Doctor record not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
