// joaofalcao
// A1Da0tg0U4exTqz4
// mongodb+srv://joaofalcao:<password>@cluster0.lly5tkp.mongodb.net/?retryWrites=true&w=majority

require("dotenv").config()
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()

// forma de ver json
app.use(express.json()) 

// Models user do mongoose
const User = require("./model/User")

// Open Route - Public Route
app.get("/", (req, res)=>{
    res.status(200).json({ msg: "welcome to our api"})
})

// Private route
app.get("/user/:id", checkToken, async(req, res)=>{
    const id = req.params.id
    // check if user exists
    const user = await User.findById(id, "-password") // retorna dados do id menos password
    if(!user){
        return res.status(404).json({msg: "usuario nao encontrado"})
    }
    res.status(200).json({ user })
})

function checkToken(req, res, next){ // este é um middleware
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]
    if(!token){
        return res.status(401).json({msg: "token invalido"})
    }
    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)   // verifica o token na secret
        next() 
    } catch (error) {
        res.status(400).json({msg: "token do try invalido"})
    }
}

// Register user
app.post("/auth/register", async(req,res) =>{
    const {name, email, password, confPassword } = req.body
    // validations
    if(!name){
        return res.status(422).json({msg: "nome é obrigatório"})
    }
    if(!email){
        return res.status(422).json({msg: "email é obrigatório"})
    }
    if(!password){
        return res.status(422).json({msg: "senha é obrigatória"})
    }
    if(password !== confPassword){
        return res.status(422).json({msg: "senha não confere"})
    }
    // check if user exists
    const userExists = await User.findOne({email: email}) // apartir da model busca no banco email
    if( userExists ){
        return res.status(422).json({msg: "email já existe"})
    }
    // create senha 
    const salt = await bcrypt.genSalt(12) // dificultador da senha
    const passwordHash = await bcrypt.hash(password, salt)
    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })
        try {
            await user.save()   // salva user criado no modelo anterior de User
            return res.status(201).json({msg: "usuario criado com sucesso"})
        } catch (error) {
            console.log(error)
            return res.status(500).json({msg:"error"})
        }

})
// login user
app.post("/auth/login", async (req,res)=>{
    const {email, password} = req.body
    // validations
    if(!email){
        return res.status(422).json({msg: "email é obrigatório"})
    }
    if(!password){
        return res.status(422).json({msg: "senha é obrigatória"})
    }
    // check if user exists
    const user = await User.findOne({email: email}) // apartir da model busca no banco email
    if( !user ){
        return res.status(422).json({msg: "email nao encontrado"})
    }
    // check if password matches
    const checkPassword = await bcrypt.compare(password, user.password) // user.password a partir do findone
    if(!checkPassword){
        return res.status(422).json({msg: "senha invalida"})
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign(
            {
            id: user._id
            },
            secret
        )
        res.status(200).json({ msg: "autenticado com sucesso", token })
    } catch (error) {
        console.log(error)
        res.status(500).json({msg: "erro, tente mais tarde"})
    }
})


// Credentials
const dbUser = process.env.DB_USER      // chama senha do dotenv instalado e configurado em .env file
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.lly5tkp.mongodb.net/?retryWrites=true&w=majority`)
.then(()=>{
    app.listen(3001)
    console.log("conectou ao banco")
})
.catch((err)=>{

})
