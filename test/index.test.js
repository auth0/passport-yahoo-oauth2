var assert = require('assert');
var util = require('util');
var yahoo = require('../lib');


describe('passport-yahoo', function() {

  it('should report a version', function () {
      assert(typeof(yahoo.version) === 'string');
  });

});
