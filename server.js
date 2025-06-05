const express = require('express');
const multer = require('multer');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8081;

// MongoDB connection (removed deprecated options)
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://aryanshtechhead:JMKKnbJh8y6IT9Fs@yearbook2025.a8vkl4u.mongodb.net/yearbook?retryWrites=true&w=majority';

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// AWS S3 v3 Configuration
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const bucketName = process.env.S3_BUCKET_NAME;

// Updated Schemas with password reset fields
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  rollNo: String, // Added rollNo for alumni
  // Add these new fields for password reset
  resetToken: String,
  lastPasswordChange: {
    type: Date,
    default: Date.now
  }
});

const memorySchema = new mongoose.Schema({
  selectedSport: String,
  selectedName: String,
  description: String,
  userName: String,
  userEmail: String,
  photo: String, // Will store S3 URL
  video: String, // Will store S3 URL
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { collection: 'responses' });

const Memory = mongoose.model('Memory', memorySchema);
const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

// CRITICAL: Block any attempts to access uploads directory BEFORE other routes
app.use((req, res, next) => {
  // Log and block any attempts to access uploads directory
  if (req.url.includes('/uploads/') || req.url.includes('uploads/')) {
    console.error('❌ Blocked attempt to access local uploads:', {
      url: req.url,
      method: req.method,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    return res.status(404).json({ 
      error: 'Files are stored in S3, not locally',
      requestedPath: req.url,
      message: 'This appears to be old data. Please refresh the page or contact support.',
      redirect: '/api/memories' // Suggest alternative
    });
  }
  next();
});

// Simple token generator for password reset
const generateSimpleToken = () => {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
};

// Multer configuration for memory storage (temporary)
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'photo') {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed for photos'));
      }
    } else if (file.fieldname === 'video') {
      if (file.mimetype.startsWith('video/')) {
        cb(null, true);
      } else {
        cb(new Error('Only video files are allowed for videos'));
      }
    } else {
      cb(new Error('Unexpected field'));
    }
  }
});

// Helper function to upload file to S3 using AWS SDK v3
const uploadToS3 = async (file, folder) => {
  const fileExtension = path.extname(file.originalname);
  const fileName = `${folder}/${uuidv4()}${fileExtension}`;
  
  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: fileName,
    Body: file.buffer,
    ContentType: file.mimetype,
  });

  try {
    await s3Client.send(command);
    const fileUrl = `https://${bucketName}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${fileName}`;
    return fileUrl;
  } catch (error) {
    console.error('S3 upload error:', error);
    throw error;
  }
};

// Helper function to delete file from S3 using AWS SDK v3
const deleteFromS3 = async (fileUrl) => {
  try {
    // Extract key from URL
    const urlParts = fileUrl.split('/');
    const key = urlParts.slice(-2).join('/'); // Get folder/filename
    
    const command = new DeleteObjectCommand({
      Bucket: bucketName,
      Key: key
    });
    
    await s3Client.send(command);
    console.log('File deleted from S3:', key);
  } catch (error) {
    console.error('S3 delete error:', error);
  }
};

// Helper function to validate URL
const isValidS3Url = (url) => {
  if (!url) return false;
  return url.startsWith('https://') && url.includes('.s3.') && url.includes('.amazonaws.com');
};

// Helper function to clean and fix memory data
const cleanMemoryData = async (memory, autoFix = false) => {
  const memoryObj = memory.toObject();
  let hasIssues = false;
  
  // Validate and clean photo URL
  if (memoryObj.photo) {
    if (!isValidS3Url(memoryObj.photo)) {
      console.warn('🔧 Cleaning invalid photo URL:', {
        memoryId: memoryObj._id,
        invalidUrl: memoryObj.photo,
        userEmail: memoryObj.userEmail
      });
      memoryObj.photo = null;
      hasIssues = true;
    }
  }
  
  // Validate and clean video URL
  if (memoryObj.video) {
    if (!isValidS3Url(memoryObj.video)) {
      console.warn('🔧 Cleaning invalid video URL:', {
        memoryId: memoryObj._id,
        invalidUrl: memoryObj.video,
        userEmail: memoryObj.userEmail
      });
      memoryObj.video = null;
      hasIssues = true;
    }
  }
  
  // Optionally, update the database record to clean it permanently
  if (hasIssues && autoFix) {
    try {
      await Memory.findByIdAndUpdate(memoryObj._id, {
        photo: memoryObj.photo,
        video: memoryObj.video
      });
      console.log('✅ Auto-fixed memory record:', memoryObj._id);
    } catch (err) {
      console.error('Error auto-fixing memory:', err);
    }
  }
  
  return memoryObj;
};

// Authentication routes
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      res.json({ 
        message: 'Login successful', 
        name: user.name, 
        email: user.email,
        rollNo: user.rollNo 
      });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
});

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    
    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Error registering user' });
  }
});

app.post('/api/alumni-register', async (req, res) => {
  const { name, rollNo, email, password } = req.body;
  
  if (!name || !rollNo || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ 
      $or: [{ email }, { rollNo }] 
    });
    
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      if (existingUser.rollNo === rollNo) {
        return res.status(400).json({ error: 'Roll number already exists' });
      }
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ name, rollNo, email, password: hashedPassword });
    await newUser.save();
    
    res.json({ message: 'Alumni registered successfully' });
  } catch (error) {
    console.error('Alumni registration error:', error);
    res.status(500).json({ error: 'Error registering alumni' });
  }
});

// PASSWORD RESET APIs

// 1. Password Reset Request API
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  // Validate IITB email
  if (!email.endsWith('@iitb.ac.in')) {
    return res.status(400).json({ error: 'Only @iitb.ac.in emails are allowed' });
  }

  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found with this email' });
    }

    // Generate simple reset token
    const resetToken = generateSimpleToken();
    
    // Save reset token to user
    user.resetToken = resetToken;
    await user.save();

    res.json({ 
      message: 'Reset token generated successfully',
      resetToken: resetToken,
      email: user.email,
      name: user.name
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Error processing password reset request' });
  }
});

// 2. Verify Reset Token API
app.post('/api/verify-reset-token', async (req, res) => {
  const { email, resetToken } = req.body;
  
  if (!email || !resetToken) {
    return res.status(400).json({ error: 'Email and reset token are required' });
  }

  try {
    const user = await User.findOne({ 
      email: email,
      resetToken: resetToken
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid email or reset token' });
    }

    res.json({ 
      valid: true, 
      email: user.email,
      name: user.name,
      message: 'Reset token is valid'
    });

  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ error: 'Error verifying reset token' });
  }
});

// 3. Reset Password API
app.post('/api/reset-password', async (req, res) => {
  const { email, resetToken, newPassword } = req.body;
  
  if (!email || !resetToken || !newPassword) {
    return res.status(400).json({ error: 'Email, reset token, and new password are required' });
  }

  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters long' });
  }

  try {
    const user = await User.findOne({
      email: email,
      resetToken: resetToken
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid email or reset token' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password and clear reset token
    user.password = hashedPassword;
    user.resetToken = null;
    user.lastPasswordChange = new Date();
    
    await user.save();

    res.json({ 
      message: 'Password reset successfully',
      email: user.email
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Error resetting password' });
  }
});

// 4. Change Password API (for logged-in users)
app.post('/api/change-password', async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;
  
  if (!email || !currentPassword || !newPassword) {
    return res.status(400).json({ 
      error: 'Email, current password, and new password are required' 
    });
  }

  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters long' });
  }

  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    
    if (!isCurrentPasswordValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    user.password = hashedNewPassword;
    user.lastPasswordChange = new Date();
    
    await user.save();

    res.json({ 
      message: 'Password changed successfully',
      email: user.email
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Error changing password' });
  }
});

// 5. Get User Info API
app.get('/api/user-info/:email', async (req, res) => {
  const { email } = req.params;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      name: user.name,
      email: user.email,
      rollNo: user.rollNo,
      lastPasswordChange: user.lastPasswordChange,
      hasResetToken: !!user.resetToken
    });

  } catch (error) {
    console.error('User info error:', error);
    res.status(500).json({ error: 'Error retrieving user information' });
  }
});

// Memory submission route with S3 integration
app.post('/api/submit', upload.fields([
  { name: 'photo', maxCount: 1 }, 
  { name: 'video', maxCount: 1 }
]), async (req, res) => {
  const { selectedSport, selectedName, description, userName, userEmail } = req.body;
  
  if (!selectedSport || !selectedName || !description || !userName || !userEmail) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }

  let photoUrl = null;
  let videoUrl = null;
  const uploadedFiles = [];

  try {
    // Upload photo to S3 if provided
    if (req.files && req.files.photo && req.files.photo[0]) {
      console.log('Uploading photo to S3...');
      photoUrl = await uploadToS3(req.files.photo[0], 'photos');
      uploadedFiles.push(photoUrl);
      console.log('Photo uploaded successfully:', photoUrl);
    }

    // Upload video to S3 if provided
    if (req.files && req.files.video && req.files.video[0]) {
      console.log('Uploading video to S3...');
      videoUrl = await uploadToS3(req.files.video[0], 'videos');
      uploadedFiles.push(videoUrl);
      console.log('Video uploaded successfully:', videoUrl);
    }

    // Create a new memory document
    const newMemory = new Memory({
      selectedSport,
      selectedName,
      description,
      userName,
      userEmail,
      photo: photoUrl,
      video: videoUrl,
    });

    // Save the memory document to MongoDB
    await newMemory.save();
    console.log('Memory saved to database successfully');

    res.json({ 
      message: 'Form submitted successfully and data saved to database',
      memoryId: newMemory._id,
      photoUrl,
      videoUrl
    });
  } catch (error) {
    console.error('Error saving memory:', error);
    
    // Clean up uploaded files if database save fails
    for (const fileUrl of uploadedFiles) {
      await deleteFromS3(fileUrl);
    }
    
    res.status(500).json({ error: 'Error saving memory to database' });
  }
});

// Get all memories route with pagination and enhanced URL validation
app.get('/api/memories', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const autoFix = req.query.autofix === 'true'; // Optional auto-fix parameter

    const memories = await Memory.find({})
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    // Clean up any invalid URLs and optionally auto-fix them
    const cleanedMemories = await Promise.all(
      memories.map(memory => cleanMemoryData(memory, autoFix))
    );
    
    const total = await Memory.countDocuments();
    
    res.json({
      memories: cleanedMemories,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalMemories: total,
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Error fetching memories:', error);
    res.status(500).json({ error: 'Error fetching memories' });
  }
});

// Get memories for a specific user
app.get('/api/memories/:email', async (req, res) => {
  try {
    const autoFix = req.query.autofix === 'true';
    const memories = await Memory.find({ userEmail: req.params.email })
      .sort({ createdAt: -1 });
    
    // Clean up any invalid URLs
    const cleanedMemories = await Promise.all(
      memories.map(memory => cleanMemoryData(memory, autoFix))
    );
    
    res.json(cleanedMemories);
  } catch (error) {
    console.error('Error fetching user memories:', error);
    res.status(500).json({ error: 'Error fetching user memories' });
  }
});

// Get memory by ID
app.get('/api/memory/:id', async (req, res) => {
  try {
    const memory = await Memory.findById(req.params.id);
    if (!memory) {
      return res.status(404).json({ error: 'Memory not found' });
    }
    
    const cleanedMemory = await cleanMemoryData(memory, true); // Auto-fix individual records
    res.json(cleanedMemory);
  } catch (error) {
    console.error('Error fetching memory:', error);
    res.status(500).json({ error: 'Error fetching memory' });
  }
});

// Delete memory route
app.delete('/api/memories/:id', async (req, res) => {
  try {
    const memory = await Memory.findById(req.params.id);
    if (!memory) {
      return res.status(404).json({ error: 'Memory not found' });
    }

    // Delete files from S3 (only if they are valid S3 URLs)
    const deletePromises = [];
    if (memory.photo && isValidS3Url(memory.photo)) {
      deletePromises.push(deleteFromS3(memory.photo));
    }
    if (memory.video && isValidS3Url(memory.video)) {
      deletePromises.push(deleteFromS3(memory.video));
    }

    await Promise.all(deletePromises);

    // Delete memory from database
    await Memory.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Memory deleted successfully' });
  } catch (error) {
    console.error('Error deleting memory:', error);
    res.status(500).json({ error: 'Error deleting memory' });
  }
});

// Search memories
app.get('/api/search', async (req, res) => {
  try {
    const { q, sport, name } = req.query;
    const autoFix = req.query.autofix === 'true';
    const query = {};

    if (q) {
      query.$or = [
        { description: { $regex: q, $options: 'i' } },
        { userName: { $regex: q, $options: 'i' } },
        { selectedName: { $regex: q, $options: 'i' } },
        { selectedSport: { $regex: q, $options: 'i' } }
      ];
    }

    if (sport) {
      query.selectedSport = { $regex: sport, $options: 'i' };
    }

    if (name) {
      query.selectedName = { $regex: name, $options: 'i' };
    }

    const memories = await Memory.find(query).sort({ createdAt: -1 });
    
    // Clean up any invalid URLs
    const cleanedMemories = await Promise.all(
      memories.map(memory => cleanMemoryData(memory, autoFix))
    );
    
    res.json(cleanedMemories);
  } catch (error) {
    console.error('Error searching memories:', error);
    res.status(500).json({ error: 'Error searching memories' });
  }
});

// Enhanced database cleanup route
app.post('/api/admin/cleanup-invalid-files', async (req, res) => {
  try {
    console.log('🔧 Starting comprehensive database cleanup...');
    
    // Find all memories with invalid file paths
    const invalidMemories = await Memory.find({
      $or: [
        { photo: { $regex: '^uploads/', $options: 'i' } },
        { video: { $regex: '^uploads/', $options: 'i' } },
        { photo: { $exists: true, $ne: null, $not: { $regex: '^https://' } } },
        { video: { $exists: true, $ne: null, $not: { $regex: '^https://' } } }
      ]
    });

    console.log(`Found ${invalidMemories.length} memories with invalid file paths`);

    let photosUpdated = 0;
    let videosUpdated = 0;

    // Process each invalid memory
    for (const memory of invalidMemories) {
      const updates = {};
      
      if (memory.photo && !isValidS3Url(memory.photo)) {
        updates.photo = null;
        photosUpdated++;
        console.log(`Cleaning photo: ${memory.photo} from memory ${memory._id}`);
      }
      
      if (memory.video && !isValidS3Url(memory.video)) {
        updates.video = null;
        videosUpdated++;
        console.log(`Cleaning video: ${memory.video} from memory ${memory._id}`);
      }

      if (Object.keys(updates).length > 0) {
        await Memory.findByIdAndUpdate(memory._id, { $set: updates });
      }
    }

    console.log(`✅ Cleanup completed: ${photosUpdated} photos, ${videosUpdated} videos cleaned`);

    res.json({
      success: true,
      message: 'Database cleanup completed successfully',
      totalMemoriesProcessed: invalidMemories.length,
      photosUpdated,
      videosUpdated,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// Automatic database fix route
app.post('/api/admin/auto-fix-database', async (req, res) => {
  try {
    console.log('🔧 Starting automatic database cleanup...');
    
    // Find all memories with invalid file paths
    const invalidMemories = await Memory.find({
      $or: [
        { photo: { $regex: '^uploads/', $options: 'i' } },
        { video: { $regex: '^uploads/', $options: 'i' } },
        { photo: { $exists: true, $ne: null, $not: { $regex: '^https://' } } },
        { video: { $exists: true, $ne: null, $not: { $regex: '^https://' } } }
      ]
    });

    console.log(`Found ${invalidMemories.length} memories with invalid file paths`);

    // Clean them up using bulk operations for better performance
    const bulkOps = invalidMemories.map(memory => {
      const updateDoc = {};
      
      if (memory.photo && !isValidS3Url(memory.photo)) {
        updateDoc.photo = null;
      }
      
      if (memory.video && !isValidS3Url(memory.video)) {
        updateDoc.video = null;
      }

      return {
        updateOne: {
          filter: { _id: memory._id },
          update: { $set: updateDoc }
        }
      };
    });

    if (bulkOps.length > 0) {
      const result = await Memory.bulkWrite(bulkOps);
      console.log(`✅ Cleaned ${result.modifiedCount} memory records`);
      
      res.json({
        success: true,
        message: 'Database cleanup completed',
        totalFound: invalidMemories.length,
        totalCleaned: result.modifiedCount,
        timestamp: new Date().toISOString()
      });
    } else {
      res.json({
        success: true,
        message: 'No invalid records found',
        totalFound: 0,
        totalCleaned: 0
      });
    }

  } catch (error) {
    console.error('Auto-fix database error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});
// Enhanced debugging route
app.get('/api/admin/check-invalid-paths', async (req, res) => {
  try {
    const memoriesWithLocalPaths = await Memory.find({
      $or: [
        { photo: { $regex: '^uploads/', $options: 'i' } },
        { video: { $regex: '^uploads/', $options: 'i' } },
        { photo: { $exists: true, $ne: null, $not: { $regex: '^https://' } } },
        { video: { $exists: true, $ne: null, $not: { $regex: '^https://' } } }
      ]
    });

    // Categorize the issues
    const issues = {
      uploadsPrefix: [],
      nonHttps: [],
      other: []
    };

    memoriesWithLocalPaths.forEach(memory => {
      const memoryData = {
        id: memory._id,
        photo: memory.photo,
        video: memory.video,
        createdAt: memory.createdAt,
        userEmail: memory.userEmail
      };

      if (memory.photo && memory.photo.startsWith('uploads/')) {
        issues.uploadsPrefix.push({ ...memoryData, field: 'photo', value: memory.photo });
      }
      if (memory.video && memory.video.startsWith('uploads/')) {
        issues.uploadsPrefix.push({ ...memoryData, field: 'video', value: memory.video });
      }
      if (memory.photo && !memory.photo.startsWith('https://') && !memory.photo.startsWith('uploads/')) {
        issues.nonHttps.push({ ...memoryData, field: 'photo', value: memory.photo });
      }
      if (memory.video && !memory.video.startsWith('https://') && !memory.video.startsWith('uploads/')) {
        issues.nonHttps.push({ ...memoryData, field: 'video', value: memory.video });
      }
    });

    res.json({
      totalInvalidMemories: memoriesWithLocalPaths.length,
      issueBreakdown: {
        uploadsPrefix: issues.uploadsPrefix.length,
        nonHttps: issues.nonHttps.length
      },
      sampleIssues: {
        uploadsPrefix: issues.uploadsPrefix.slice(0, 5),
        nonHttps: issues.nonHttps.slice(0, 5)
      },
      canAutoFix: true,
      recommendedAction: 'Run POST /api/admin/cleanup-invalid-files to fix these issues'
    });
  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Health check route
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    s3Connected: !!bucketName,
    mongoConnected: mongoose.connection.readyState === 1,
    environment: process.env.NODE_ENV || 'development',
    fileStorage: 'S3 Only - Local uploads blocked'
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  // Enhanced error logging for file-related errors
  if (error.code === 'ENOENT') {
    console.error('🚨 ENOENT Error Details:', {
      message: error.message,
      path: error.path,
      errno: error.errno,
      code: error.code,
      syscall: error.syscall,
      requestUrl: req.url,
      requestMethod: req.method,
      timestamp: new Date().toISOString()
    });
    
    return res.status(404).json({ 
      error: 'File not found. Files are stored in S3, not locally.',
      message: 'This may be caused by old data. Please try refreshing or contact support.',
      suggestion: 'If this persists, run the database cleanup: POST /api/admin/cleanup-invalid-files'
    });
  }
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ error: 'Unexpected file field.' });
    }
  }
  
  if (error.message.includes('Only image files') || error.message.includes('Only video files')) {
    return res.status(400).json({ error: error.message });
  }
  
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`S3 Bucket: ${bucketName || 'Not configured'}`);
  console.log('All file operations are configured for S3 storage');
  console.log('Local uploads directory access is BLOCKED');
  console.log('To fix database issues, run: POST /api/admin/cleanup-invalid-files');
});