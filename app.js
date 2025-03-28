const express = require('express');
const { Pool } = require("pg");
const dotenv = require("dotenv");
const path=require('path');
const hbs=require('hbs');
const cookieParser=require("cookie-parser");
const app = express();

dotenv.config({
    path: './.env',

});
const pool = new Pool({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
    port: process.env.PORT,
});

pool.connect((err) => {
    if (err) {
        console.log(err);

    } else {
        console.log("PostgreSql connection success");

    }
});
app.use(cookieParser());
app.use(express.urlencoded({extended:false}));

const location=path.join(__dirname,"./public");
app.use(express.static(location));
app.set('view engine','hbs');

const partialspath=path.join(__dirname, "./views/partials");
hbs.registerPartials(partialspath);
app.use('/',require('./routes/pages'));
app.use('/auth',require('./routes/auth'));


app.listen(5000, () => {
    console.log("server started @ port 5000");
});
