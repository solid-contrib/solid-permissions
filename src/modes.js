'use strict'
/**
 * Exports acl-related constants
 * @module modes
 */
const vocab = require('solid-namespace')
const ns = vocab()

// ACL access modes
const READ = ns.acl('Read')
const WRITE = ns.acl('Write')
const APPEND = ns.acl('Append')
const CONTROL = ns.acl('Control')
const EVERYONE = ns.foaf('Agent')
const ALL_MODES = [ READ, WRITE, CONTROL ]

// ACL-related convenience constants
const INHERIT = true
const NOT_INHERIT = !INHERIT
const ACCESS_TO = 'accessTo'
const DEFAULT = 'default'

module.exports.acl = {
  ALL_MODES,
  READ,
  WRITE,
  APPEND,
  CONTROL,
  EVERYONE,
  INHERIT,
  NOT_INHERIT,
  ACCESS_TO,
  DEFAULT
}
