// Generated by CoffeeScript 1.12.7

/*
Asynchronous enumeration

Returns:
  cb(error):      error
  cb(null, crt):  certificate
  cb():           done
 */
var crypt;

crypt = require('./crypt32');

module.exports = function(cb) {
  var croak, free, more, store;
  store = null;
  crypt.CertOpenSystemStoreA.async(null, 'ROOT', function(error, result) {
    if (croak(error)) {
      return;
    }
    store = result;
    return more(null);
  });
  free = function() {
    if (!store) {
      return;
    }
    crypt.CertCloseStore.async(store, 0, function() {});
    return store = 0;
  };
  croak = function(error) {
    if (!error) {
      return;
    }
    free();
    cb(error);
    return true;
  };
  return more = function(ctx) {
    return crypt.CertEnumCertificatesInStore.async(store, ctx, function(error, result) {
      if (croak(error)) {
        return;
      }
      try {
        if (result.isNull()) {
          free();
          setImmediate(cb);
          return;
        }
        cb(null, result.deref().crt());
        return more(result);
      } catch (error1) {
        error = error1;
        free();
        return cb(error);
      }
    });
  };
};