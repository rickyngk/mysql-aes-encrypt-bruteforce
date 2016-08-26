/*
Test
Mysql: node . 81f44672f7707f551ea23c36b66f7afe
*/

var ProgressBar = require('progress');
var process = require('process');
var MySqlAES128 = require('./mysql-aes-128');

var args = process.argv.slice(2);
var input = args[0];
if (!input) {
  console.log('Invalid input');
  process.exit();
}
console.log('[+] Start cracking', input);

var bar;
var m = new MySqlAES128({set: {number: 1}});
m.bruteForce(input, {maxKeyLength: 8, minKeyLength: 1, breakInFirstResult: 1}, (i, n) => {
  if (!bar) {
    bar = new ProgressBar('[:bar] :percent :current/:total :eta', { total: n, width: 40, incomplete: '.' , callback: ()=> {console.log(m.candidates);}});
  }
  bar.update(i/n);
});