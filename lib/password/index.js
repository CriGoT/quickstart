'use strict';

const crypto = require('crypto');

const iterations = process.env.PASSSWOR_ITERATIONS || 10000;
const digest = process.env.PASSWORD_DIGEST || 'sha512';
const saltLength = process.env.PASSWORD_SALT_LENGTH || 32;
const keyLength = process.env.PASSWORD_KEY_LENGTH || 64;

const hash = (password) => new Promise((resolve, reject) =>{
  crypto.randomBytes(saltLength, (err, salt) => {
    if (err) return reject(err);
    crypto.pbkdf2(password, salt, iterations, keyLength, digest, (err, hash) => {
      if (err) return reject(err);

      resolve([
        salt.toString('hex'),
        iterations,
        keyLength,
        digest,
        hash.toString('hex') ].join('$'));
    });
  });
})

const compare = (hashString, password) => new Promise((resolve, reject) => {
  const [
    salt,
    iterations,
    keyLength,
    digest,
    hash
  ] = hashString.split('$');

  crypto.pbkdf2(password, Buffer.from(salt, 'hex'), parseInt(iterations), parseInt(keyLength), digest, (err, computedHash) => {
    if (err) return reject(err);

    resolve(Buffer.compare(computedHash, Buffer.from(hash, 'hex')) === 0);
  });
});

module.exports = {
  hash,
  compare
}
