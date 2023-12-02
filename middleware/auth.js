const jwt = require('jsonwebtoken')

const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')
    if(!token){
        return res.status(401).json({message: 'Unauthorized'})
    }
    try{
        const verified = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET)
        req.user = verified
        next()
    } catch(err){
        res.status(400).json({message: 'Invalid token'})
    }
}

const verifyAdmin = (req, res, next) => {
    if(req.user.role !== 'admin'){
        return res.status(401).json({message: 'Unauthorized'})
    }
    next()
}

module.exports = { verifyToken, verifyAdmin }    