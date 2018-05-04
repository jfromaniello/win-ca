###
Enumerate system root CAs synchronously
###
crypt = require './crypt32'

module.exports = (storeName, cb)->
  if typeof storeName == 'function'
    cb = storeName
    storeName = 'ROOT'

  if Array.isArray(storeName)
    storeName.forEach (sn) -> module.exports sn, cb
    return;

  store = crypt.CertOpenSystemStoreA null, storeName
  try
    ctx = null
    while 1
      ctx = crypt.CertEnumCertificatesInStore store, ctx
      return if ctx.isNull()
      cb ctx.deref().crt()
  finally
    crypt.CertCloseStore store, 0
