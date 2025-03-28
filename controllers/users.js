const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const { log, error } = require("console");

const pool = new Pool({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
    ssl: {
        rejectUnauthorized: false, 
        require: true,
    },
    types: {
        getTypeParser: () => (val) => val
    }
});

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).render('login', {
                msg: 'please Enter Your Email and Password', msg_type: "error",
            });
        }
        pool.query('SELECT * FROM users WHERE email = $1', [email], async (error, result) => {
            console.log(result);
            if (result.rows.length === 0) {
                return res.status(401).render("login", {
                    msg: 'Email or Password is Incorrect..', msg_type: "error",
                });
            } else {
                if (!(await bcrypt.compare(password, result.rows[0].password))) {
                    return res.status(401).render("login", {
                        msg: ' please enter your Email and Password .', msg_type: "error",
                    });

                } else {
                    const id = result.rows[0].id;
                    const token = jwt.sign({ id: id }, process.env.JWT_SECRET, {
                        expiresIn: process.env.JWT_EXPIRES_IN,
                    });
                    console.log("The token is" + token);
                    const cookiesOptions = {
                        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                        httpOnly: true,
                    };
                    res.cookie("joes", token, cookiesOptions);
                    res.status(200).redirect("/home");
                }
            }


        });

    } catch (error) {
        console.log(error);

    }

};
exports.register = (req, res) => {
    /*console.log(req.body);
    const name=req.body.name;
    const email=req.body.email;
    const password=req.body.password;
    const confirm_password=req.body.confirm_password;*/
    //res.send("Form Submitted");
    const { name, email, password, confirm_password } = req.body;
    pool.query('SELECT email FROM users WHERE email = CAST($1 AS TEXT)', [email],
        async (error, result) => {
            if (error) {
                console.log(error);

            }
            if (result.rows.length > 0) {
                return res.render('register', { msg: 'email id already Taken', msg_type: "error" });
            } else if (password !== confirm_password) {
                return res.render('register', { msg: "password do not match", msg_type: "error" });
            }
            let hashedPassword = await bcrypt.hash(password, 8);

            pool.query(
                'INSERT INTO users (name, email, password) VALUES ($1, $2, $3)',
                [name, email, hashedPassword], (error, result) => {
                    if (error) {
                        console.log(error);

                    } else {
                        console.log(result);
                        return res.render("register", { msg: "user registration success", msg_type: "good" });

                    }
                });
        })

};

exports.isLoggedIn = async (req, res, next) => {
    //console.log(req.cookies);
    if (req.cookies.joes) {
        try {
            const decode = await promisify(jwt.verify)(
                req.cookies.joes,
                process.env.JWT_SECRET
            )
            console.log(decode);

            pool.query("select * from users where id=$1",[decode.id],(error,results)=>{
               // console.log(results);
               if(!results){
                return next();
               }
               req.user=results.rows[0];
               return next();
                

              });

        } catch (error) {
            console.log(error);
            return next();

        }
    }
       else {
            next();
        }

  

};
exports.logout=async(req,res)=>{
    res.cookie("joes","logout",{
        expires:new Date(Date.now()+2*1000),
        httpOnly:true,
    });
    res.status(200).redirect("/");
}