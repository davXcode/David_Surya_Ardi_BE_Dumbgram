// import package here
const multer = require('multer');

exports.uploadFile = (imageFile) => {
  // Destionation & rename file
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads');
    },
    filename: function (req, file, cb) {
      cb(null, Date.now() + file.originalname.replace(/\s/g, ''));
    },
  });

  // Filter file extension
  const fileFilter = function (req, file, cb) {
    if (file.fieldname == imageFile) {
      if (!file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG)$/)) {
        req.fileValidationError = {
          message: 'Only image files are allowed!',
        };
        return cb(new Error('Only image files are allowed!', false));
      }
    }
    cb(null, true);
  };

  // Maximum file size
  // MB -> KB -> byte
  const sizeInMB = 10;
  const maxSize = sizeInMB * 1000 * 1000;

  const upload = multer({
    storage,
    fileFilter,
    limits: {
      fileSize: maxSize,
    },
  }).single(imageFile);

  // HANDLER required, if error, if LIMIT SIZE

  return (req, res, next) => {
    upload(req, res, function (err) {
      // if filter error
      if (req.fileValidationError) {
        return res.status(400).send(req.fileValidationError);
      }

      // if file doesn't provided
      if (!req.file && !err) {
        return res.status(400).send({
          messsage: 'Please select files to upload',
        });
      }

      // if exceed the max size
      if (err) {
        if (err.code == 'LIMIT_FILE_SIZE') {
          return res.status(400).send({
            messsage: 'Max file size 10Mb',
          });
        }
        return res.status(400).send(err);
      }

      // if all okay
      return next();
    });
  };
};
