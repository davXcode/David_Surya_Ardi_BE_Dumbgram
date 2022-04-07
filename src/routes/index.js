const express = require('express'); // import express

const router = express.Router(); //give access

// Controller
const {
  addUsers,
  getUsers,
  getUser,
  updateUser,
  deleteUser,
} = require('../controllers/user'); // import user
const { getProduct, getproduct, updateProduct, deleteProduct, addProduct } = require('../controllers/product'); // import product
const {
  getTransactions,
  addTransaction,
} = require('../controllers/transaction'); // import transaction
const { register, login } = require('../controllers/auth'); // import register & Login

const { addCategory, getCategory, updateCategory, deleteCategory } = require('../controllers/category'); // import category

// Middleware
const { auth } = require('../middlewares/auth');
const { uploadFile } = require('../middlewares/uploadFile');

// Route User
router.post('/user', addUsers); // add user
router.get('/users', getUsers); // get user
router.get('/user/:id', getUser); // get user detail
router.patch('/user/:id', updateUser); // update user
router.delete('/user/:id', deleteUser); // delete user

// Route Product
router.get('/products', auth, getProduct); // get product
router.post('/product', auth, uploadFile('image'), addProduct); // place middleware before controller | add product
router.get('/product/:id', getproduct); //get product detail
router.patch('/product/:id', updateProduct); //update product
router.delete('/product/:id', deleteProduct); // Delete Product

// Route Category
router.post('/category', auth, addCategory); // add category
router.get('/category', auth, getCategory); // get category
router.get('/category/:id', auth, getCategory); //get category detail
router.patch('/category/:id', auth, updateCategory); // update category
router.delete('/category/:id', auth, deleteCategory); // delete category

// Route Transaction
router.get('/transactions', auth, getTransactions);
router.post('/transaction', auth, addTransaction);

// Register
router.post('/register', register); // register new user
router.post('/login', login); // login user

module.exports = router;
