// Generated by CoffeeScript 1.12.7

/*
Save Root CAs to disk
 */
var all, dst, format, fs, hach, hash, hex, mkdir, path;

fs = require('fs');

path = require('path');

all = require('./all');

mkdir = require('./mkdir');

format = require('./format');

hash = require('./hash');

hach = require('./hash_old');

exports.path = dst = path.join(__dirname, '../pem');

hex = function(hash) {
  var x;
  x = hash.toString(16);
  while (x.length < 8) {
    x = '0' + x;
  }
  return x;
};

mkdir(dst, function() {
  var drop, hashes, list, name, names, save;
  process.env.SSL_CERT_DIR = dst;
  list = all.slice();
  hashes = {};
  names = {};
  name = function(hash) {
    var n, x;
    x = hex(hash);
    hashes[x] || (hashes[x] = 0);
    n = hashes[x]++;
    n = x + "." + n;
    names[n] = 1;
    return n;
  };
  drop = function() {
    return fs.readdir(dst, function(err, files) {
      if (err) {
        throw err;
      }
      return (drop = function() {
        var file;
        if (!(file = files.pop())) {
          return;
        }
        if (names[file]) {
          setImmediate(drop);
          return;
        }
        return fs.unlink(path.join(dst, file), function(err) {
          if (err) {
            throw err;
          }
          return drop();
        });
      })();
    });
  };
  return (save = function() {
    var crt, pem;
    if (!(crt = list.pop())) {
      drop();
      return;
    }
    return fs.writeFile(path.join(dst, pem = name(hash(crt.subject))), format(crt), function(err) {
      var link;
      if (err) {
        throw err;
      }
      return fs.unlink(link = path.join(dst, name(hach(crt.subject))), function(err) {
        return fs.copyFile(path.join(dst, pem), link, function(err) {
          if (err) {
            throw err;
          }
          return save();
        });
      });
    });
  })();
});