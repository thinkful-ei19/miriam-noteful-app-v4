'use strict';

const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const { TEST_MONGODB_URI } = require('../config');

const User = require('../models/user');

const expect = chai.expect;

chai.use(chaiHttp);

describe('Noteful API - Users', function () {
    const username = 'exampleUser';
    const password = 'examplePass';
    const fullname = 'Example User';

    before(function () {
        return mongoose.connect(TEST_MONGODB_URI)
            .then(() => mongoose.connection.db.dropDatabase());
    });

    beforeEach(function () {
        // noop
    });

    afterEach(function () {
        return mongoose.connection.db.dropDatabase();
    });

    after(function () {
        return mongoose.disconnect();
    });

    describe('/api/users', function () {
        describe('POST', function () {
            it('Should create a new user', function () {
                const testUser = { username, password, fullname };
                let res;
                return chai
                    .request(app)
                    .post('/api/users')
                    .send(testUser)
                    .then(_res => {
                        res = _res;
                        expect(res).to.have.status(201);
                        expect(res.body).to.be.an('object');
                        expect(res.body).to.have.keys('id', 'username', 'fullname');

                        expect(res.body.id).to.exist;
                        expect(res.body.username).to.equal(testUser.username);
                        expect(res.body.fullname).to.equal(testUser.fullname);

                        return User.findOne({ username });
                    })
                    .then(user => {
                        expect(user).to.exist;
                        expect(user.id).to.equal(res.body.id);
                        expect(user.fullname).to.equal(testUser.fullname);
                        return user.validatePassword(password);
                    })
                    .then(isValid => {
                        expect(isValid).to.be.true;
                    });
            });

            it('Should reject users with missing username', function () {
                const testUser = { password, fullname };
                return chai
                    .request(app)
                    .post('/api/users')
                    .send(testUser)
                    .then(() =>
                        // somehow bad testUser is accepted
                        expect.fail(null, null, 'Request should not succeed')    
                    )
                    .catch(err => {
                        if (err instanceof chai.AssertionError) {
                            throw err;
                        }
                        const res = err.response;
                        expect(res).to.have.status(422);
                        // would have to have defined reason and location
                        // expect(res.body.reason).to.equal('ValidationError');
                        expect(res.body.message).to.equal('Missing \'username\' in request body');
                        // expect(res.body.location).to.equal('username');
                    });
            });

            it('Should reject users with missing password', function () {
                const testUser = { username, fullname };
                return chai
                    .request(app)
                    .post('/api/users')
                    .send(testUser)
                    .then(() =>
                        // somehow bad testUser is accepted
                        expect.fail(null, null, 'Request should not succeed')    
                    )
                    .catch(err => {
                        if (err instanceof chai.AssertionError) {
                            throw err;
                        }
                        const res = err.response;
                        expect(res).to.have.status(422);
                        // would have to have defined reason and location
                        // expect(res.body.reason).to.equal('ValidationError');
                        expect(res.body.message).to.equal('Missing \'password\' in request body');
                        // expect(res.body.location).to.equal('username');
                    });
            });

            it('Should reject users with non-string username', function() {
                return chai
                    .request(app)
                    .post('/api/users')
                    .send({
                        username: 1234,
                        password,
                        fullname
                    })
                    .then(() =>
                        expect.fail(null, null, 'Request should not succeed')
                    )
                    .catch(err => {
                        if (err instanceof chai.AssertionError) {
                            throw err;
                      }
          
                      const res = err.response;
                      expect(res).to.have.status(422);
                    //   expect(res.body.reason).to.equal('ValidationError');
                      expect(res.body.message).to.equal(
                        'Field: \'username\' is not type String'
                      );
                    //  expect(res.body.location).to.equal('username');
                    });
            });

            it('Should reject users with non-string password', function() {
                return chai
                    .request(app)
                    .post('/api/users')
                    .send({
                        username, 
                        password: 1234,
                        fullname
                    })
                    .then(() =>
                        expect.fail(null, null, 'Request should not succeed')
                    )
                    .catch(err => {
                        if (err instanceof chai.AssertionError) {
                            throw err;
                      }
          
                      const res = err.response;
                      expect(res).to.have.status(422);
                    //   expect(res.body.reason).to.equal('ValidationError');
                      expect(res.body.message).to.equal(
                        'Field: \'password\' is not type String'
                      );
                    //  expect(res.body.location).to.equal('username');
                    });
            });
 
            it('Should reject users with non-trimmed username', function() {
                return chai
                    .request(app)
                    .post('/api/users')
                    .send({
                        username: ` ${username} `,
                        password,
                        fullname
                    })
                    .then(() =>
                        expect.fail(null, null, 'Request should not succeed')
                    )
                    .catch(err => {
                        if (err instanceof chai.AssertionError) {
                            throw err;
                        }
      
                        const res = err.response;
                        expect(res).to.have.status(422);
                        // expect(res.body.reason).to.equal('ValidationError');
                        expect(res.body.message).to.equal(
                            'Cannot start or end with whitespace'
                        );
                        // expect(res.body.location).to.equal('username');
                    });
            });
                     
            
  
            it('Should reject users with non-trimmed password', function() {
                return chai
                    .request(app)
                    .post('/api/users')
                    .send({
                        username,
                        password: ` ${password} `,
                        fullname
                    })
                    .then(() =>
                        expect.fail(null, null, 'Request should not succeed')
                    )
                    .catch(err => {
                        if (err instanceof chai.AssertionError) {
                            throw err;
                        }
      
                        const res = err.response;
                        expect(res).to.have.status(422);
                        // expect(res.body.reason).to.equal('ValidationError');
                        expect(res.body.message).to.equal(
                            'Cannot start or end with whitespace'
                        );
                        // expect(res.body.location).to.equal('username');
                    });
            });           

            it('Should reject users with empty username', function () {
                return chai
                .request(app)
                .post('/api/users')
                .send({
                    username: '',
                    password,
                    fullname
                })
                .then(()=> 
                    expect.fail(null,null, 'Request should not succeed')
                )
                .catch(err => {
                    if (err instanceof chai.AssertionError) {
                        throw err;
                    }
                    const res = err.response;
                    expect(res).to.have.status(422);
                    // expect(res.reason).to.equal('ValidationError');
                    expect(res.body.message).to.equal(
                        'Field: \'username\' must be at least 1 characters long'
                    )
                })
            });


            it('Should reject users with password less than 8 characters', function () {
                return chai
                  .request(app)
                  .post('/api/users')
                  .send({
                    username,
                    password: '1234567',
                    fullname
                  })
                  .then(() =>
                    expect.fail(null, null, 'Request should not succeed')
                  )
                  .catch(err => {
                    if (err instanceof chai.AssertionError) {
                      throw err;
                    }
        
                    const res = err.response;
                    expect(res).to.have.status(422);
                    // expect(res.body.reason).to.equal('ValidationError');
                    expect(res.body.message).to.equal(
                      'Field: \'password\' must be at least 8 characters long'
                    );
                    // expect(res.body.location).to.equal('password');
                  });
              });
        
            it('Should reject users with password greater than 72 characters', function () {
                return chai
                  .request(app)
                  .post('/api/users')
                  .send({
                    username,
                    password: new Array(73).fill('z').join(''),
                    fullname
                  })
                  .then(() =>
                    expect.fail(null, null, 'Request should not succeed')
                  )
                  .catch(err => {
                    if (err instanceof chai.AssertionError) {
                      throw err;
                    }
        
                    const res = err.response;
                    expect(res).to.have.status(422);
                    // expect(res.body.reason).to.equal('ValidationError');
                    expect(res.body.message).to.equal(
                        `Field: \'password\' must be at most 72 characters long`
                    );
                    // expect(res.body.location).to.equal('password');
                  });
            });

            it('Should reject users with duplicate username', function() {
            // Create an initial user
            return User.create({
                username,
                password,
                fullname
            })
                .then(() =>
                // Try to create a second user with the same username
                chai.request(app).post('/api/users').send({
                    username,
                    password,
                    fullname
                })
                )
                .catch(err => {
                if (err instanceof chai.AssertionError) {
                    throw err;
                }
    
                const res = err.response;
                expect(res).to.have.status(400);
                // expect(res.body.reason).to.equal('ValidationError');
                expect(res.body.message).to.equal(
                    'Username already taken'
                );
                // expect(res.body.location).to.equal('username');
                });
            });


            it('Should trim fullname', function() {
                return chai
                    .request(app)
                    .post('/api/users')
                    .send({
                        username,
                        password,
                        fullname: ` ${fullname} `
                        })
                    .then(res => {
                        expect(res).to.have.status(201);
                        expect(res.body).to.be.an('object');
                        expect(res.body).to.have.keys(
                            'username',
                            'fullname',
                            'id'
                            );
                        expect(res.body.username).to.equal(username);
                        expect(res.body.fullname).to.equal(fullname);
                        return User.findOne({
                            username
                        });
                    })
                    .then(user => {
                        expect(user).to.not.be.null;
                        expect(user.fullname).to.equal(fullname);
                     });
            });    





            /**
             * COMPLETE ALL THE FOLLOWING TESTS
             */
        });

        // describe('GET', function () {
        //     it('Should return an empty array initially', function () {
        //         return chai.request(app).get('/api/users')
        //             .then(res => {
        //                 expect(res).to.have.status(200);
        //                 expect(res.body).to.be.an('array');
        //                 expect(res.body).to.have.length(0);
        //             });
        //     });
        //     it('Should return an array of users', function () {
        //         const testUser0 = {
        //             username: `${username}`,
        //             password: `${password}`,
        //             fullname: ` ${fullname} `
        //         };
        //         const testUser1 = {
        //             username: `${username}1`,
        //             password: `${password}1`,
        //             fullname: `${fullname}1`
        //         };
        //         const testUser2 = {
        //             username: `${username}2`,
        //             password: `${password}2`,
        //             fullname: `${fullname}2`
        //         };

        //         /**
        //          * CREATE THE REQUEST AND MAKE ASSERTIONS
        //          */
        //     });
        // });
    });
});