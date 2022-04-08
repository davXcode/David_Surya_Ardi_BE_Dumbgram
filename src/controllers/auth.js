// import model
const { user } = require("../../models");

// import joi validation
const joi = require("joi");
// import bcrypt
const bcrypt = require("bcrypt");
// import jsonwebtoken
const jwt = require("jsonwebtoken");

// Register
exports.register = async (req, res) => {


  let data = req.body

  // Auto customer
  if(!data.status){
      data = {
          ...data,
          status: 'customer',
      };
  };

  // Validation
  const schema = joi.object({
      name:joi.string().min(4).required(),
      email:joi.string().email().required(),
      password:joi.string().min(6).required(),
      status:joi.string(),
  });

  const { error }= schema.validate(data);

  if (error) {
      return res.send({
          error:{
              message: error.details[0].message,
          },
      });
  }

  // check if email exist
  const dataInDB = await user.findOne({
      where: {
          email: data.email
      }
  })

  if(dataInDB){
      return res.status(400).send({
          error: {
              message: `Email ${data.email} is Already`,
          }
      })
  }
  try {

  const hashedPassword = await bcrypt.hash(req.body.password, 10)

  const newUser = await user.create({
      name: data.name,
      email: data.email,
      password: hashedPassword,
      status: data.status,
  })


  // generate token
  const token = jwt.sign({ id: user.id }, process.env.TOKEN_KEY);

  res.status(200).send({
      status: 'success',
      data:{
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          token,
      }
  });

} catch (error) {
  console.log(error)
  res.status(500).send({
      status: 'failed',
      message:'server error',
  })
}

};

// Login
exports.login = async (req, res) => {
  const data = req.body

        const schema = joi.object({
            email:joi.string().email().required(),
            password:joi.string().min(6).required(),
        });

        const { error }= schema.validate(data)
        if (error) {
            return res.send({
                error:{
                    message: error.details[0].message,
                },
            });
        }
        try {

        const userExist = await user.findOne({
            where: {
                email: data.email,
            },
        });

        if(!userExist){
            return res.send({
                error: {
                    message: `Email or password not match;`
                },
            });
        }

        const isValid = await bcrypt.compare(req.body.password, userExist.password)

        if(!isValid){
            return res.status(400).send({
                status:'failed',
                message:'Email or password not match',
            })
        }

        // Generate Token
        const token = jwt.sign({ id: userExist.id }, process.env.TOKEN_KEY);

        res.status(200).send({
            status: 'success',
            data:{
                id: userExist.id,
                name: userExist.name,
                email: userExist.email,
                status: userExist.status,
                token,
            }
        });

    } catch (error) {
        console.log(error)
        res.status(500).send({
            status: 'failed',
            message:'server error',
        })
    }

};