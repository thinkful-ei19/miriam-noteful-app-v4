'use strict';

const express = require('express');
const router = express.Router();

const app = express();
const passport = require('passport');

const mongoose = require('mongoose');

const Tag = require('../models/tag');
const Note = require('../models/note');

// require authoriztion to use tags api methods
const userAuth = passport.authenticate('jwt', { session: false, failWithError: true });


/* ========== GET/READ ALL ITEMS ========== */
router.get('/tags', userAuth, (req, res, next) => {
  const userId = req.user.id;

  let filter = { userId };

  Tag.find(filter)
    .sort('name')
    .then(results => {
      res.json(results);
    })
    .catch(err => {
      next(err);
    });
});

/* ========== GET/READ A SINGLE ITEM ========== */
router.get('/tags/:id', userAuth, (req, res, next) => {
  const { id } = req.params;
  const userId = req.user.id;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    const err = new Error('The `id` is not valid');
    err.status = 400;
    return next(err);
  }
 
  let filter = { userId };

  Tag.findOne( { _id: id, userId} )
    .then(result => {
      if (result) {
        res.json(result);
      } else {
        next();
      }
    })
    .catch(err => {
      next(err);
    });
});

/* ========== POST/CREATE AN ITEM ========== */
router.post('/tags', userAuth, (req, res, next) => {
  const { name } = req.body;
  const userId = req.user.id;

  const newTag = { name, userId };

  /***** Never trust users - validate input *****/
  if (!name) {
    const err = new Error('Missing `name` in request body');
    err.status = 400;
    return next(err);
  }

  Tag.create(newTag)
    .then(result => {
      res.location(`${req.originalUrl}/${result.id}`).status(201).json(result);
    })
    .catch(err => {
      if (err.code === 11000) {
        err = new Error('The tag name already exists');
        err.status = 400;
      }
      next(err);
    });
});

/* ========== PUT/UPDATE A SINGLE ITEM ========== */
router.put('/tags/:id', userAuth, (req, res, next) => {
  const { id } = req.params;
  const { name } = req.body;
  const { userId } = req.user.id;
  const updateItem = { name }

  /***** Never trust users - validate input *****/
  if (!name) {
    const err = new Error('Missing `name` in request body');
    err.status = 400;
    return next(err);
  }

  if (!mongoose.Types.ObjectId.isValid(id)) {
    const err = new Error('The `id` is not valid');
    err.status = 400;
    return next(err);
  }

  const updateTag = { name };

  Tag.findOneAndUpdate( { _id: id, userId }, updateTag, { new: true })
    .then(result => {
      if (result) {
        res.json(result);
      } else {
        next();
      }
    })
    .catch(err => {
      if (err.code === 11000) {
        err = new Error('The tag name already exists');
        err.status = 400;
      }
      next(err);
    });
});

/* ========== DELETE/REMOVE A SINGLE ITEM ========== */
router.delete('/tags/:id', userAuth, (req, res, next) => {
  const { id } = req.params;
  const userId = req.user.id;

 // *** promise only for tag id and user id   *****
 const tagRemovePromise = Tag.findOneAndRemove( { _id: id, userId} );

  const noteUpdatePromise = Note.updateMany(
    { 'tags': id, },
    { '$pull': { 'tags': id } }
  );

  Promise.all([tagRemovePromise, noteUpdatePromise])
    .then(([tagResult]) => {
      if (tagResult) {
        res.status(204).end();
      } else {
        next();
      }
    })
    .catch(err => {
      next(err); });

});

module.exports = router;