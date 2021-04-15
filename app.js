require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())
app.use(express.urlencoded({extended:false}))

let accounts = []

app.post('/register',(req,res) => {
   const {username,password} = req.body
    accounts.push({
        username:username,
        password:password
    })
    res.send(accounts)
})


app.post('/login',(req,res) => {
    const {username,password} = req.body
    if (!username||!password) return res.json({status:{error:true,message:'username and password are required'}})
    const existedUser = accounts.filter(x=>x.username==username)
    if (existedUser.length===0) return res.json({status:{error:true,message:'Not found username in DB'}})

    if (existedUser[0].password!==password) return res.json({status:{error:true,message:'incorrect password'}})

    const token = jwt.sign({user:username},process.env.TOKEN,{expiresIn: '15s'})
    const refreshToken = jwt.sign({user:username},process.env.REFRESH,{expiresIn: '180d'})

    accounts.map(x=>{
        if(x.username==username)
        x.refreshToken = refreshToken
    })

    res.json({token:token,refreshToken:refreshToken})
})



app.post('/refresh',(req,res)=>{
    const {token} = req.body
    if (!token) return res.status(401).json({status:{error:true,message:'Not found input token'}})

    if(accounts.filter(x=>x.refreshToken==token).length==0) return res.status(401).json({status:{error:true,message:'Not found input token'}})

    try {
      const data = jwt.verify(token,process.env.REFRESH)
      const newToken = jwt.sign({user:data.user},process.env.TOKEN,{expiresIn:'15s'})
      res.json({token:newToken})
    } catch {
        return  res.status(403).json({status:{error:true,message:'Invalid Token'}})
    }
    
})


app.delete('/logout',(req,res)=>{
    const {token} = req.body
    if (!token) return res.status(401).json({status:{error:true,message:'Not found input token'}})

    accounts.map(x=>{
        if (x.refreshToken==token) x.refreshToken=""
    })

    res.json(accounts)
})



const jwtAuth = (req,res,next)=>{
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token==null) return res.status(401).json({status:{error:true,message:'Not found input token'}})

    let verified
    try {
        verified = jwt.verify(token,process.env.TOKEN)
        req.user = verified.user
        next()
    } catch  {
        return  res.status(403).json({status:{error:true,message:'Invalid Token'}})
    }
     
    
}

app.get('/',jwtAuth,(req,res)=>{
    res.send(req.user)
})

app.listen(process.env.PORT,()=>{console.log(`Server is running at http://localhost:${process.env.PORT}`)})