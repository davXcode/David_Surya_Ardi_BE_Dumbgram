const { product, user, category, productCategory } = require('../../models');

// Get all product
exports.getProduct = async (req, res) => {
  try {

    // sort fitur
    let data = "";
        let sortNameAsc = false;
        let sortNameDsc = false; // name z to a
        let sortPriceAsc = true;
        let sortPriceDsc = false; // high price to lower price

        if(sortNameAsc == true){
             data = await product.findAll({
                order: [['name', 'ASC']],
                attributes: {
                  exclude: ['createdAt', 'updatedAt'],
                }
              });
        };
        if(sortNameDsc == true){
            data = await product.findAll({
               order: [['name', 'DESC']],
               attributes: {
                 exclude: ['createdAt', 'updatedAt'],
               }
             });
       };
        if(sortPriceAsc == true){
             data = await product.findAll({
                order: [['price', 'ASC']],
                attributes: {
                  exclude: ['createdAt', 'updatedAt'],
                }
              });
        };
        if(sortPriceDsc == true){
            data = await product.findAll({
               order: [['price', 'DESC']],
               attributes: {
                 exclude: ['createdAt', 'updatedAt'],
               }
             });
       };
        if(sortPriceAsc == false && sortPriceDsc == false && sortNameAsc == false && sortNameDsc == false){
             data = await product.findAll({
                attributes: {
                  exclude: ['createdAt', 'updatedAt'],
                }
              });
        };

    // Path File image
    data = data.map((item) => {
      item.image = process.env.PATH_FILE + item.image;
      return item;
    });

    res.send({
      status: 'success...',
      data,
    });
  } catch (error) {
    console.log(error);
    res.send({
      status: 'failed',
      message: 'Server Error',
    });
  }
};

// Get product detail
exports.getproduct = async (req, res) => {
  try {
    const id = req.params.id
    const data = await product.findOne({
      attributes:{
          exclude:['createdAt','updatedAt']
      },
      where:{
          id,
      }
    });

    res.send({
      status: 'success',
      data,
    });
  } catch (error) {
    console.log(error);
    res.send({
      status:'failed',
      message: 'server error',
    });
  }
};

// Update Product
exports.updateProduct = async (req, res) => {
  try {
      const id = req.params.id;
      const data = req.body;
      await product.update(req.body, {
          where: {
              id,
          },
      });
  
      res.send({
          status: 'success',
          data:{
            product:{
            id,
            data,
          }
        }
      });
    } catch (error) {
    console.log(error);
    res.send({
      status:'failed',
      message: 'server error',
    });
  }
};

// Delete product
exports.deleteProduct = async (req, res) => {
  try {
    const { id } = req.params;

    await product.destroy({
      where: { 
        id,
      },
    }),

    res.send({
      status: "success",
      message: `Delete product with id: ${id} success`,
    });
  } catch (error) {
    console.log(error);
    res.send({
      status: "failed",
      message: "server error",
    });
  }
};

// Add Product
exports.addProduct = async (req, res) => {
  try {
    const data = req.body;

    data.idUser = req.user.id;
    data.image = req.file.filename;

    const newProduct = await product.create(data);

    let productData = await product.findOne({
      where: {
        id: newProduct.id,
      },
      include: [
        {
          model: user,
          as: 'user',
          attributes: {
            exclude: ['createdAt', 'updatedAt', 'password'],
          },
        },
      ],
      attributes: {
        exclude: ['createdAt', 'updatedAt', 'idUser'],
      },
    });

    res.send({
      status: 'success',
      data: {
        productData,
      },
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      status: 'failed',
      message: 'Server Error',
    });
  }
};
