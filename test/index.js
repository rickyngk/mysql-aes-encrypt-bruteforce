var MySqlAES128 = require('../mysql-aes-128');
var expect = require('chai').expect;

describe('Test MySqlAES128', function() {
  it('#Case 1: number only', function(done) {
    this.timeout(99999999999);
    var m = new MySqlAES128({set: {number: 1}});
    m.bruteForce('81f44672f7707f551ea23c36b66f7afe', {maxKeyLength: 3}, (i, n) => {
      if (i == n) {
        expect(m.candidates).to.eql([['123', '123']]);
        done();
      }
    });
  });
});