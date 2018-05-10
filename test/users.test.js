'use strict';


const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');

const { TEST_MONGODB_URI } = require('../config');

const User = require('../models/users');
const seedUsers = require('../db/seed/users');

const expect = chai.expect;

chai.use(chaiHttp);

console.log('TESTING RESULTS:', TEST_MONGODB_URI);

describe.only('Noteful API - Users', function () {
  const username = 'exampleUser';
  const password = 'examplePass';
  const fullname = 'Example User';

  before(function () {
    return mongoose.connect(TEST_MONGODB_URI)
      .then(() => mongoose.connection.db.dropDatabase());
  });

  beforeEach(function () {
    return User.createIndexes();
  });

  afterEach(function () {
    return mongoose.connection.db.dropDatabase();
  });

  after(function () {
    return mongoose.disconnect();
  });


  // before(function () {
  //   return mongoose.connect(TEST_MONGODB_URI);
  //   // .then(() => mongoose.connection.db.dropDatabase());
  // });

  // beforeEach(function () {
  //   return mongoose.connection.db.dropDatabase()
  //     .then(() => {
  //       User.insertMany(seedUsers)
  //         .then(()=> {return User.createIndexes();});
  //     });
  // });

  // afterEach(function () {
  //   return mongoose.connection.db.dropDatabase();
  // });

  // after(function () {
  //   return mongoose.disconnect();
  // });





  
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
        return chai.request(app).post('/api/users').send(testUser)
          .then(res => {

            /**
             * CREATE YOUR ASSERTIONS HERE
             */

          });
      });

      /**
       * COMPLETE ALL THE FOLLOWING TESTS
       */
      it('Should reject users with missing password');
      it('Should reject users with non-string username');
      it('Should reject users with non-string password');
      it('Should reject users with non-trimmed username');
      it('Should reject users with non-trimmed password');
      it('Should reject users with empty username');
      it('Should reject users with password less than 8 characters');
      it('Should reject users with password greater than 72 characters');
      it('Should reject users with duplicate username');
      it('Should trim fullname');
    });

    describe('GET', function () {
      it('Should return an empty array initially', function () {
        return chai.request(app).get('/api/users')
          .then(res => {
            expect(res).to.have.status(200);
            expect(res.body).to.be.an('array');
            expect(res.body).to.have.length(0);
          });
      });
      it('Should return an array of users', function () {
        const testUser0 = {
          username: `${username}`,
          password: `${password}`,
          fullname: ` ${fullname} `
        };
        const testUser1 = {
          username: `${username}1`,
          password: `${password}1`,
          fullname: `${fullname}1`
        };
        const testUser2 = {
          username: `${username}2`,
          password: `${password}2`,
          fullname: `${fullname}2`
        };

        /**
         * CREATE THE REQUEST AND MAKE ASSERTIONS
         */
      });
    });
  });
});