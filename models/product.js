"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class product extends Model {
    
    static associate(models) {
      // define association here
      product.belongsTo(models.user, {
        as: "user",
        foreignKey: {
          name: "idUser",
        },
      });

      product.hasMany(models.transaction, {
        as: "transactions",
        foreignKey: {
          name: "idProduct",
        },
      });

      // belongs to many category
      product.belongsToMany(models.category, {
        as: "categories",
        through: {
          model: "productCategory",
          as: "bridge",
        },
        foreignKey: "idProduct",
      });
    }
  }
  product.init(
    {
      name: DataTypes.STRING,
      desc: DataTypes.TEXT,
      price: DataTypes.INTEGER,
      image: DataTypes.STRING,
      qty: DataTypes.INTEGER,
      idUser: DataTypes.INTEGER,
    },
    {
      sequelize,
      modelName: "product",
    }
  );
  return product;
};
