// Generated by CoffeeScript 1.12.7

/*
Format Certificate output
 */
var formats;

module.exports = function(crt) {
  return formats(crt).join('\n');
};

formats = function(crt) {
  var k, ref, results, s, v;
  ref = require('./formats');
  results = [];
  for (k in ref) {
    v = ref[k];
    s = v(crt);
    if (v.join != null) {
      s = s.join(v.join);
    }
    if (false !== v.title) {
      s = (k.replace(/./, function(s) {
        return s.toUpperCase();
      })) + "\t" + s;
    }
    results.push(s);
  }
  return results;
};