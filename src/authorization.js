'use strict'
/**
 * Models a single Authorization, as part of a PermissionSet.
 * @see https://github.com/solid/web-access-control-spec for details.
 * @module authorization
 */

var hash = require('shorthash')
var vocab = require('solid-namespace')

/**
 * Returns a set of convenience constants, for use with `addPermission()` etc.
 * Exported as `Authorization.acl`.
 */
function modes () {
  var ns = vocab()
  var acl = {
    'READ': ns.acl('Read'),
    'WRITE': ns.acl('Write'),
    'APPEND': ns.acl('Append'),
    'CONTROL': ns.acl('Control'),
    'EVERYONE': ns.foaf('Agent')
  }
  return acl
}

/**
 * Inherited authorization (acl:defaultForNew)
 * @type {Boolean}
 */
var INHERIT = true

/**
 * Models an individual authorization object, for a single resource and for
 * a single webId (either agent or agentClass). See the comments at the top
 * of the PermissionSet module for design assumptions.
 * Low-level, not really meant to be instantiated directly. Use
 * `permissionSet.addPermission()` instead.
 * @class Authorization
 */
class Authorization {
  /**
   * @param resourceUrl {String} URL of the resource (`acl:accessTo`) for which
   *   this authorization is intended.
   * @param [inherited] {Boolean} Should this authorization be inherited (contain
   *   `acl:default`). Used for container ACLs. Defaults to null/false.
   * @constructor
   */
  constructor (resourceUrl, inherited) {
    /**
     * Hashmap of all of the access modes (`acl:Write` etc) granted to an agent
     * or group in this authorization. Modified via `addMode()` and `removeMode()`
     * @property accessModes
     * @type {Object}
     */
    this.accessModes = {}
    /**
     * URL of an agent's WebID (`acl:agent`). Inside an authorization, mutually
     * exclusive with the `group` property. Set via `setAgent()`.
     * @property agent
     * @type {String}
     */
    this.agent = null
    /**
     * URL of a group resource (`acl:agentClass`). Inside an authorization,
     * mutually exclusive with the `agent` property. Set via `setGroup()`.
     * @property group
     * @type {String}
     */
    this.group = null
    /**
     * Does this authorization apply to the contents of a container?
     * (`acl:default`). Not used with non-container resources.
     * @property inherited
     * @type {Boolean}
     */
    this.inherited = inherited
    /**
     * Stores the `mailto:` aliases for a given agent. Semi-unofficial
     * functionality, used to store a user's email in the root storage .acl,
     * to use for account recovery etc.
     * @property mailTo
     * @type {Array<String>}
     */
    this.mailTo = []
    /**
     * Hashmap of which origins (http Origin: header) are allowed access to this
     * resource.
     * @property originsAllowed
     * @type {Object}
     */
    this.originsAllowed = {}
    /**
     * URL of the resource for which this authorization applies. (`acl:accessTo`)
     * @property resourceUrl
     * @type {String}
     */
    this.resourceUrl = resourceUrl
  }

  /**
   * Adds a given `mailto:` alias to this authorization.
   * @method addMailTo
   * @param agent {String|Statement} Agent URL (or RDF `acl:agent` statement).
   */
  addMailTo (agent) {
    if (typeof agent !== 'string') {
      agent = agent.object.uri
    }
    if (agent.startsWith('mailto:')) {
      agent = agent.split(':')[ 1 ]
    }
    this.mailTo.push(agent)
    this.mailTo.sort()
  }

  /**
   * Adds one or more access modes (`acl:mode` statements) to this authorization.
   * @method addMode
   * @param accessMode {String|Statement|Array<String>|Array<Statement>} One or
   *   more access modes, each as either a uri, or an RDF statement.
   * @return {Authorization} Returns self, chainable.
   */
  addMode (accessMode) {
    var self = this
    if (Array.isArray(accessMode)) {
      accessMode.forEach((ea) => {
        self.addModeSingle(ea)
      })
    } else {
      self.addModeSingle(accessMode)
    }
    return self
  }

  /**
   * Adds a single access mode. Internal function, used by `addMode()`.
   * @method addModeSingle
   * @private
   * @param accessMode {String|Statement} Access mode as either a uri, or an RDF
   *   statement.
   */
  addModeSingle (accessMode) {
    if (typeof accessMode !== 'string') {
      accessMode = accessMode.object.uri
    }
    this.accessModes[ accessMode ] = true
    return this
  }

  /**
   * Adds one or more allowed origins (`acl:origin` statements) to this
   * authorization.
   * @method addOrigin
   * @param origin {String|Statement|Array<String>|Array<Statement>} One or
   *   more origins, each as either a uri, or an RDF statement.
   * @return {Authorization} Returns self, chainable.
   */
  addOrigin (origin) {
    var self = this
    if (Array.isArray(origin)) {
      origin.forEach((ea) => {
        self.addOriginSingle(ea)
      })
    } else {
      self.addOriginSingle(origin)
    }
    return self
  }

  /**
   * Adds a single allowed origin. Internal function, used by `addOrigin()`.
   * @method addOriginSingle
   * @private
   * @param origin {String|Statement} Allowed origin as either a uri, or an RDF
   *   statement.
   */
  addOriginSingle (origin) {
    if (typeof origin !== 'string') {
      origin = origin.object.uri
    }
    this.originsAllowed[ origin ] = true
    return this
  }

  /**
   * Returns a list of all access modes for this authorization.
   * @method allModes
   * @return {Array<String>}
   */
  allModes () {
    return Object.keys(this.accessModes)
  }

  /**
   * Returns a list of all allowed origins for this authorization.
   * @method allOrigins
   * @return {Array<String>}
   */
  allOrigins () {
    return Object.keys(this.originsAllowed)
  }

  /**
   * Tests whether this authorization grant the specified access mode
   * @param accessMode {String}
   * @return {Boolean}
   */
  allowsMode (accessMode) {
    // Normalize the access mode
    accessMode = Authorization.acl[accessMode.toUpperCase()] || accessMode
    return this.accessModes[accessMode]
  }
  /**
   * Does this authorization grant access to requests coming from given origin?
   * @method allowsOrigin
   * @param origin {String}
   * @return {Boolean}
   */
  allowsOrigin (origin) {
    return origin in this.originsAllowed
  }

  /**
   * Does this authorization grant `acl:Read` access mode?
   * @method allowsRead
   * @return {Boolean}
   */
  allowsRead () {
    return this.accessModes[ Authorization.acl.READ ]
  }

  /**
   * Does this authorization grant `acl:Write` access mode?
   * @method allowsWrite
   * @return {Boolean}
   */
  allowsWrite () {
    return this.accessModes[ Authorization.acl.WRITE ]
  }

  /**
   * Does this authorization grant `acl:Append` access mode?
   * @method allowsAppend
   * @return {Boolean}
   */
  allowsAppend () {
    return this.accessModes[ Authorization.acl.APPEND ] ||
      this.accessModes[ Authorization.acl.WRITE ]
  }

  /**
   * Does this authorization grant `acl:Control` access mode?
   * @method allowsControl
   * @return {Boolean}
   */
  allowsControl () {
    return this.accessModes[ Authorization.acl.CONTROL ]
  }

  /**
   * Compares this authorization with another one.
   * Authorizations are equal iff they:
   *   - Are for the same agent or group
   *   - Are intended for the same resourceUrl
   *   - Grant the same access modes
   *   - Have the same `inherit`/`acl:default` flag
   *   - Contain the same `mailto:` agent aliases.
   *   - Has the same allowed origins
   * @method equals
   * @param auth {Authorization}
   * @return {Boolean}
   */
  equals (auth) {
    var sameAgent = this.agent === auth.agent
    var sameGroup = this.group === auth.group
    var sameUrl = this.resourceUrl === auth.resourceUrl
    var myModeKeys = Object.keys(this.accessModes)
    var authModeKeys = Object.keys(auth.accessModes)
    var sameNumberModes = myModeKeys.length === authModeKeys.length
    var sameInherit =
      JSON.stringify(this.inherited) === JSON.stringify(auth.inherited)
    var sameModes = true
    myModeKeys.forEach((key) => {
      if (!auth.accessModes[ key ]) { sameModes = false }
    })
    var sameMailTos = JSON.stringify(this.mailTo) === JSON.stringify(auth.mailTo)
    var sameOrigins =
      JSON.stringify(this.originsAllowed) === JSON.stringify(auth.originsAllowed)
    return sameAgent && sameGroup && sameUrl && sameNumberModes && sameModes &&
      sameInherit && sameMailTos && sameOrigins
  }

  /**
   * Returns a hashed combination of agent/group webId and resourceUrl. Used
   * internally as a key to store this authorization in a PermissionSet.
   * @method hashFragment
   * @private
   * @throws {Error} Errors if either the webId or the resourceUrl are not set.
   * @return {String} hash({webId}-{resourceUrl})
   */
  hashFragment () {
    if (!this.webId || !this.resourceUrl) {
      throw new Error('Cannot call hashFragment() on an incomplete authorization')
    }
    var hashFragment = hashFragmentFor(this.webId(), this.resourceUrl)
    return hashFragment
  }

  /**
   * Returns whether or not this authorization is for an agent (vs a group).
   * @method isAgent
   * @return {Boolean} Truthy value if agent is set
   */
  isAgent () {
    return this.agent
  }

  /**
   * Returns whether or not this authorization is empty (that is, whether it has
   * any access modes like Read, Write, etc, set on it)
   * @method isEmpty
   * @return {Boolean}
   */
  isEmpty () {
    return Object.keys(this.accessModes).length === 0
  }

  /**
   * Is this authorization intended for the foaf:Agent group (that is, everyone)?
   * @method isPublic
   * @return {Boolean}
   */
  isPublic () {
    return this.group === Authorization.acl.EVERYONE
  }

  /**
   * Returns whether or not this authorization is for a group (vs an agent).
   * @method isGroup
   * @return {Boolean} Truthy value if group is set
   */
  isGroup () {
    return this.group
  }

  /**
   * Returns whether this authorization is for a container and should be inherited
   * (that is, contain `acl:default`).
   * This is a helper function (instead of the raw attribute) to match the rest
   * of the api.
   * @method isInherited
   * @return {Boolean}
   */
  isInherited () {
    return this.inherited
  }

  /**
   * Returns whether this authorization is valid (ready to be serialized into
   * an RDF graph ACL resource). This requires all three of the following:
   *   1. Either an agent or an agentClass/group (returned by `webId()`)
   *   2. A resource URL (`acl:accessTo`)
   *   3. At least one access mode (read, write, etc) (returned by `isEmpty()`)
   * @method isValid
   * @return {Boolean}
   */
  isValid () {
    return this.webId() &&
      this.resourceUrl && !this.isEmpty()
  }

  /**
   * Merges the access modes of a given authorization with the access modes of
   * this one (Set union).
   * @method mergeWith
   * @param auth
   * @throws {Error} Error if the other authorization is for a different webId
   *   or resourceUrl (`acl:accessTo`)
   */
  mergeWith (auth) {
    if (this.hashFragment() !== auth.hashFragment()) {
      throw new Error('Cannot merge authorizations with different agent id or resource url (accessTo)')
    }
    for (var accessMode in auth.accessModes) {
      this.addMode(accessMode)
    }
  }

  /**
   * Returns an array of RDF statements representing this authorization.
   * Used by `PermissionSet.serialize()`.
   * @method rdfStatements
   * @return {Array<Statement>} List of RDF statements representing this Auth,
   *   or an empty array if this authorization is invalid.
   */
  rdfStatements (rdf) {
    // Make sure the authorization has at least one agent/group and `accessTo`
    if (!this.webId() || !this.resourceUrl) {
      return []  // This Authorization is invalid, return empty array
    }
    var statement
    var fragment = rdf.namedNode('#' + this.hashFragment())
    var ns = vocab(rdf)
    var statements = [
      rdf.triple(
        fragment,
        ns.rdf('type'),
        ns.acl('Authorization'))
    ]
    if (this.agent) {
      statement = rdf.triple(fragment, ns.acl('agent'), rdf.namedNode(this.agent))
      statements.push(statement)
    }
    if (this.mailTo.length > 0) {
      this.mailTo.forEach((agentMailto) => {
        statement = rdf.triple(fragment, ns.acl('agent'),
          rdf.namedNode('mailto:' + agentMailto))
        statements.push(statement)
      })
    }
    if (this.group) {
      statement = rdf.triple(fragment, ns.acl('agentClass'),
        rdf.namedNode(this.group))
      statements.push(statement)
    }
    statement = rdf.triple(fragment, ns.acl('accessTo'),
      rdf.namedNode(this.resourceUrl))
    statements.push(statement)
    var modes = Object.keys(this.accessModes)
    modes.forEach((accessMode) => {
      statement = rdf.triple(fragment, ns.acl('mode'), rdf.namedNode(accessMode))
      statements.push(statement)
    })
    if (this.inherited) {
      statement = rdf.triple(fragment, ns.acl('defaultForNew'),
        rdf.namedNode(this.resourceUrl))
      statements.push(statement)
    }
    this.allOrigins().forEach((origin) => {
      statement = rdf.triple(fragment, ns.acl('origin'), rdf.namedNode(origin))
      statements.push(statement)
    })
    return statements
  }

  /**
   * Removes one or more access modes from this authorization.
   * @method removeMode
   * @param accessMode {String|Statement|Array<String>|Array<Statement>} URL
   *   representation of the access mode, or an RDF `acl:mode` triple.
   * @returns {removeMode}
   */
  removeMode (accessMode) {
    var self = this
    if (Array.isArray(accessMode)) {
      accessMode.forEach((ea) => {
        self.removeModeSingle(ea)
      })
    } else {
      self.removeModeSingle(accessMode)
    }
    return self
  }

  /**
   * Removes a single access mode from this authorization. Internal use only
   * (used by `removeMode()`).
   * @method removeModeSingle
   * @private
   * @param accessMode {String|Statement} URI or RDF statement
   */
  removeModeSingle (accessMode) {
    if (typeof accessMode !== 'string') {
      accessMode = accessMode.object.uri
    }
    delete this.accessModes[ accessMode ]
  }

  /**
   * Removes one or more allowed origins from this authorization.
   * @method removeOrigin
   * @param origin {String|Statement|Array<String>|Array<Statement>} URL
   *   representation of the access mode, or an RDF `acl:mode` triple.
   * @returns {removeMode}
   */
  removeOrigin (accessMode) {
    var self = this
    if (Array.isArray(accessMode)) {
      accessMode.forEach((ea) => {
        self.removeOriginSingle(ea)
      })
    } else {
      self.removeOriginSingle(accessMode)
    }
    return self
  }

  /**
   * Removes a single allowed origin from this authorization. Internal use only
   * (used by `removeOrigin()`).
   * @method removeOriginSingle
   * @private
   * @param origin {String|Statement} URI or RDF statement
   */
  removeOriginSingle (origin) {
    if (typeof origin !== 'string') {
      origin = origin.object.uri
    }
    delete this.originsAllowed[ origin ]
  }

  /**
   * Sets the agent WebID for this authorization. Implemented as `setAgent()`
   * setter method to enforce mutual exclusivity with `group` property, until
   * ES6 setter methods become available.
   * @method setAgent
   * @param agent {String|Statement} Agent URL (or `acl:agent` RDF triple).
   */
  setAgent (agent) {
    if (typeof agent !== 'string') {
      // This is an RDF statement
      agent = agent.object.uri
    }
    if (agent === Authorization.acl.EVERYONE) {
      this.setPublic()
    } else if (this.group) {
      throw new Error('Cannot set agent, authorization already has a group set')
    }
    if (agent.startsWith('mailto:')) {
      this.addMailTo(agent)
    } else {
      this.agent = agent
    }
  }

  /**
   * Sets the group WebID for this authorization. Implemented as `setGroup()`
   * setter method to enforce mutual exclusivity with `agent` property, until
   * ES6 setter methods become available.
   * @method setGroup
   * @param agentClass {String|Statement} Group URL (or `acl:agentClass` RDF
   *   triple).
   */
  setGroup (agentClass) {
    if (typeof agentClass !== 'string') {
      // This is an RDF statement
      agentClass = agentClass.object.uri
    }
    if (this.agent) {
      throw new Error('Cannot set group, authorization already has an agent set')
    }
    this.group = agentClass
  }

  /**
   * Sets the authorization's group to `foaf:Agent`. Convenience method.
   * @method setPublic
   */
  setPublic () {
    this.setGroup(Authorization.acl.EVERYONE)
  }

  /**
   * Returns the agent or group's WebID for this authorization.
   * @method webId
   * @return {String}
   */
  webId () {
    return this.agent || this.group
  }
}
// --- Standalone (non-instance) functions --

/**
 * Utility method that creates a hash fragment key for this authorization.
 * Used with graph serialization to RDF, and as a key to store authorizations
 * in a PermissionSet. Exported (mainly for use in PermissionSet).
 * @method hashFragmentFor
 * @param webId {String}
 * @param resourceUrl {String}
 * @return {String}
 */
function hashFragmentFor (webId, resourceUrl) {
  var hashKey = webId + '-' + resourceUrl
  return hash.unique(hashKey)
}
Authorization.acl = modes()
Authorization.hashFragmentFor = hashFragmentFor
Authorization.INHERIT = INHERIT

module.exports = Authorization
