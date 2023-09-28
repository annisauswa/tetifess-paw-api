const User = require('../model/user')
const Posting = require('../model/posting')

const deleteUser = async (req, res) => {
    const userId = req.params.userId;

    try {
        // Find the user by ID
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete all posts associated with the user
        await Posting.deleteMany({ userId: userId });

        // Delete the user
        await User.findByIdAndDelete(userId);

        res.status(200).json({ message: 'User and associated posts deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
}

const updateUser = async (req, res) => {
    const userId = req.params.userId
    const { username, name, bio } = req.body;
    try {
        if (username == null && name == null && bio == null){
            return res.status(200).json({ message: "Nothing to update"  });
        } else {
            if (username != null) {
                const existingUser = await User.findOne({ username: username });
                
                if (existingUser && String(existingUser._id) !== String(userId)) {
                    return res.status(400).json({ message: "Username exists, insert new one." });
                }
            }
            const updatedUser = await User.findByIdAndUpdate(userId, {"$set":{ username: username, name: name, bio: bio, dateEdited: Date.now()}});

            if (!updatedUser) {
                return res.status(404).json({ error: "User not found" });
            }

            res.status(200).json({ message: "Update successful"  });
        }
    } catch (err) {
        res.json({err})
        res.status(500).json({ message: 'Internal server error' })
    }
}

const getUsers = async (req, res) => {
    const userId = req.params.userId;

    try{
        if (userId){
            const users = await User.findById(userId)
            .populate({path:'likedPostings', select:'userId text', model: Posting, populate: {path: 'userId', select: 'username'}})
            
            if (!users){
                return res.status(404).json({ message: 'User not found' })
            }
            return res.json(users)
        } else {
            try{
                const users = await User.find()
                .populate({path:'likedPostings', select:'_id userId text', model: Posting, populate: {path: 'userId', select: 'username'}})
                res.json(users)
            } catch(err){
                res.json({err})
                res.status(500).json({ message: 'Internal server error' })
            } 
        }
    } catch(err){
        res.status(500).json({ message: 'Insert user ID' })
    }

}

const editPosting = async (req, res) => {
    const postId = req.params.postId;
    const message = req.body;

    try {
        const editedPost = await Posting.findByIdAndUpdate(postId, { $set: message}, {new: true}).populate({path:'userId', select:'_id username name'});

        if (!editedPost) {
            res.status(404).json({ message: 'Post not found' });
        } else {
            res.json(editedPost);
        }
    } catch (err) {
        res.json(err.message)
    }
}

module.exports = {
    deleteUser,
    updateUser,
    getUsers,
    editPosting
}