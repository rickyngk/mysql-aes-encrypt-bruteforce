var crypto = require('crypto');
class MySqlAES128 {
  constructor(opt) {
    opt = opt || {};
    opt.set = opt.set || {number: 1, lower: 1, upper: 1, special: 1};
    this.chars = [];
    this.next = [];
    this.candidates = [];
    var prev = null;
    var numbers = []; if (opt.set.number) for (let i = 48; i <= 57; i++) { numbers.push(String.fromCharCode(i)); }
    var lowerCases = []; if (opt.set.lower) for (let i = 65; i <= 90; i++) { lowerCases.push(String.fromCharCode(i)); }
    var upperCases = []; if (opt.set.upper) for (let i = 97; i <= 122; i++) { upperCases.push(String.fromCharCode(i)); }
    var special = []; if (opt.set.special) special = [' ', '`', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '=', ',', '.', '/', ';', ':', '|', '?', '<', '>', '[', ']', '{', '}', '\\', '\'', '"'];

    this.chars = [].concat(numbers).concat(lowerCases).concat(upperCases).concat(special);

    for (let i = 0; i < this.chars.length; i++) {
      let c = this.chars[i];
      if (prev != null) {
        this.next[prev] = c;
      }
      prev = c;
    }
    this.next[this.chars[this.chars.length - 1]] = this.chars[0];
    this.lastkey = this.chars[0];
  }

  _isReadableText(txt) {
    return txt.split('').every(e => e >= ' ' && e <= '~');
  }

  convertCryptKey(strKey) {
    var newKey = new Buffer([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    strKey = new Buffer(strKey);
    for(var i=0;i<strKey.length;i++) newKey[i%16]^=strKey[i];
    return newKey;
  }

  encrypt(txt, password) {
    var c = crypto.createCipheriv('aes-128-ecb', this.convertCryptKey(password), '');
    return c.update(txt, 'utf8', 'hex') + c.final('hex');
  }

  decrypt(hexa, password) {
    try {
      var dc = crypto.createDecipheriv('aes-128-ecb', this.convertCryptKey(password), '');
      return dc.update(hexa, 'hex', 'utf8') + dc.final('utf8');
    } catch (e) {
      return null;
    }
  }

  firstChar() {return this.chars[0];}

  getAKey(last) {
    var len = last.length;
    var tmp = last.split('');

    var endOfSegment = true;
    for (let i = len - 1; i >= 0; i--) {
      tmp[i] = this.next[last[i]];
      if (tmp[i] != this.chars[0]) {
        endOfSegment = false;
        break;
      }
    }
    if (endOfSegment) tmp.push(this.chars[0]);
    return tmp.join('');
  }

  tryNext(input) {
    let k = this.lastkey;
    var v = this.decrypt(input, k);
    this.lastkey = this.getAKey(k);
    if (v && this._isReadableText(v)) {
      this.candidates.push([k, v]);
    }
  }

  bruteForce(input, opt, cb) {
    opt = opt || {};
    opt.minKeyLength = Math.max(parseInt(opt.minKeyLength) || 1, 1);
    opt.maxKeyLength = Math.max(Math.min(parseInt(opt.maxKeyLength) || 16, 32), opt.minKeyLength);
    opt.breakInFirstResult = opt.breakInFirstResult || false;
    this.lastkey = '';
    for (let i = 0; i < opt.minKeyLength; i++) {
      this.lastkey += this.chars[0];
    }
    var nTry = Math.pow(this.chars.length, opt.maxKeyLength) - Math.pow(this.chars.length, opt.minKeyLength - 1);
    var self = this;
    let tick = (i, n) => {
      cb(i, n);
      for (let j = 0; j < 100000 & i + j <= n; j++) {
        self.tryNext(input);
        if (opt.breakInFirstResult && self.candidates.length > 0) {
          i = n;
          cb(n, n);
          break;
        }
      }
      if (i < n) {
        setTimeout((i, n) => {
          tick(i+100000, n);
        }, 0, i, n);
      }
    };
    tick(1, nTry);
  }
}

module.exports = MySqlAES128;