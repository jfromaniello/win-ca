require './format.oids'

@all = ->
  require './all'

require './inject'
@path =  require './save'
  .path

@each = require './each'

@async = (cb)->
  require('./async') cb
