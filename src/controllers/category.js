const { product, user, category, productCategory } = require('../../models');

// Add Category
exports.addCategory = async (req, res) => {
    try{

        const data = req.body;
        const newCategory = await category.create(data);
      
        let productData = await category.findOne({
          where: {
            id: newCategory.id,
          },
          attributes: {
            exclude: ['createdAt', 'updatedAt'],
          },
        });
      
        res.send({
          status: 'success',
          data:{
            category:{
              id: productData.id,
              name: productData.name,
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

// get Category
exports.getCategory = async (req, res) => {
    try {
    const data = await category.findAll({
        attributes:{
        exclude:['createdAt','updatedAt']
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

// get Category details
exports.getCategory = async (req, res) => {
    try {
    const data = await category.findAll({
        attributes:{
        exclude:['createdAt','updatedAt']
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

// Update category
exports.updateCategory = async (req, res) => {
    try {
        const id = req.params.id;
        const data = req.body;
        await category.update(req.body, {
            where: {
                id,
            },
        });

        res.send({
            status: 'success',
            data:{
                category:{
                id,
                data,
                }
            }
        });
    } catch (error) {
        console.log(error);
        res.send({
            status: 'failed',
            message: 'server error',
        });
    }
};

// delete category
exports.deleteCategory = async (req, res) => {
    try {
        const { id } = req.params;

        await category.destroy({
            where: {
                id,
            },
        }),

        res.send({
            status: "success",
            message: `Delete Category with id: ${id} success`,
        });
    } catch (error) {
        console.log(error);
        res.send({
            status: "failed",
            message: "server error",
        });
    }
};