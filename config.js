'use strict';

exports.PORT = process.env.PORT || 8080;

exports.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost/noteful';

exports.TEST_MONGODB_URI = process.env.TEST_MONGODB_URI ||'mongodb://dev:dev@ds111430.mlab.com:11430/noteful-test';
// || 'mongodb://dev:dev@ds111430.mlab.com:11430/noteful-test' || process.env.TEST_MONGODB_URI || 'mongodb://localhost/noteful-test';



exports.JWT_SECRET = process.env.JWT_SECRET || 'secret';
exports.JWT_EXPIRY = process.env.JWT_EXPIRY || '7d';