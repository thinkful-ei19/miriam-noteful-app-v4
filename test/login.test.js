'use strict';

const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const { JWT_SECRET, TEST_MONGODB_URI } = require('../config');

const User = require('../models/user');

const seedUsers = require('../db/seed/users');

const expect = chai.expect;

chai.use(chaiHttp);

describe('Noteful API - Login', function () {
    before(function () {
        return mongoose.connect(TEST_MONGODB_URI)
            .then(() => mongoose.connection.db.dropDatabase());
    });

    beforeEach(function () {
        const testUser = seedUsers[0];
        return User.hashPassword(testUser.password)
            .then(digest => {
                return User.create({
                    _id: testUser._id,
                    fullname: testUser.fullname,
                    username: testUser.username,
                    password: digest
                })
            })
    });

    afterEach(function () {
        return mongoose.connection.db.dropDatabase();
        // alternatively you can just drop the user
        // return User.remove();
    });

    after(function () {
        return mongoose.disconnect();
    });

    describe.only('Noteful /api/login', function () {
        it('Should return a valid auth token', function () {
            // const { _id: id, username, fullname } = seedUsers[0];
            return chai
                .request(app)
                .post('/api/login')
                .send({ username: 'user0', password: 'password0' })
                .then(res => {

                    expect(res).to.have.status(200);
                    expect(res.body).to.be.an('object');
                    expect(res.body.authToken).to.be.a('string');
                    
                    const payload = jwt.verify(res.body.authToken, JWT_SECRET);

                    expect(payload.user).to.not.have.property('password');
                    expect(payload.user).to.deep.equal({
                        "id": "333333333333333333333300",
                        "fullname": "User Zero",
                        "username": "user0",
                      });
                });
        });

        it('Should reject requests with no credentials', function () {
            return chai
                .request(app)
                .post('/api/login')
                // omit .send or each test of "no credentials" works
                .send( {username: '', password: ''} )              
                // .send()
                // .send( {} )
                .then(() =>
                  expect.fail(null, null, 'Request should not succeed')
                )
                .catch(err => {
                  if (err instanceof chai.AssertionError) {
                    throw err;
                  }        
                  const res = err.response;
                  expect(res).to.have.status(400);
                });
        });
        
        it('Should reject requests with incorrect usernames', function () {
            return chai
                .request(app)
                .post('/api/login')
                .send({ username: 'wrongUsername', password: 'password0' })
                .then(() =>
                    expect.fail(null, null, 'Request should not succeed')
                )
                .catch(err => {
                    if (err instanceof chai.AssertionError) {
                        throw err;
                    }
      
                    const res = err.response;
                    expect(res).to.have.status(401);
              });
          });


        it('Should reject requests with incorrect passwords', function () {
        return chai
            .request(app)
            .post('/api/login')
            .send({ username:'user0', password: 'wrongPassword' })
            .then(() =>
            expect.fail(null, null, 'Request should not succeed')
            )
            .catch(err => {
            if (err instanceof chai.AssertionError) {
                throw err;
            }

            const res = err.response;
            expect(res).to.have.status(401);
            });
        });





    });
});