'use strict'
/**
 * Models a single Permission, as part of a PermissionSet.
 * @see https://github.com/solid/web-access-control-spec for details.
 * @module permission
 */

const vocab = require('solid-namespace')
const { acl } = require('./modes')
const GroupListing = require('./group-listing')

/**
 * Models an individual permission object, for a single resource and for
 * a single webId (either agent or group). See the comments at the top
 * of the PermissionSet module for design assumptions.
 * Low-level, not really meant to be instantiated directly. Use
 * `permissionSet.addPermission()` instead.
 * @class Permission
 */
class Permission {
  /**
   * @param resourceUrl {String} URL of the resource (`acl:accessTo`) for which
   *   this permission is intended.
   * @param [inherited=false] {Boolean} Should this permission be inherited (contain
   *   `acl:default`). Used for container ACLs.
   * @constructor
   */
  constructor (resourceUrl, inherited = false) {
    /**
     * Hashmap of all of the access modes (`acl:Write` etc) granted to an agent
     * or group in this permission. Modified via `addMode()` and `removeMode()`
     * @property accessModes
     * @type {Object}
     */
    this.accessModes = {}
    /**
     * Type of permission, either for a specific resource ('accessTo'),
     * or to be inherited by all downstream resources ('default')
     * @property accessType
     * @type {String} Either 'accessTo' or 'default'
     */
    this.accessType = inherited
      ? acl.DEFAULT
      : acl.ACCESS_TO
    /**
     * URL of an agent's WebID (`acl:agent`). Inside an permission, mutually
     * exclusive with the `group` property. Set via `setAgent()`.
     * @property agent
     * @type {String}
     */
    this.agent = null
    /**
     * URL of a group resource (`acl:agentGroup` or `acl:agentClass`). Inside an
     * permission, mutually exclusive with the `agent` property.
     * Set via `setGroup()`.
     * @property group
     * @type {String}
     */
    this.group = null
    /**
     * Does this permission apply to the contents of a container?
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
     * URL of the resource for which this permission applies. (`acl:accessTo`)
     * @property resourceUrl
     * @type {String}
     */
    this.resourceUrl = resourceUrl
    /**
     * Should this permission be serialized? (When writing back to an ACL
     * resource, for example.) Used for implied (rather than explicit)
     * permission, such as ones that are derived from acl:Control statements.
     * @property virtual
     * @type {Boolean}
     */
    this.virtual = false
  }

  /**
   * Adds a given `mailto:` alias to this permission.
   * @method addMailTo
   * @param agent {String|Statement} Agent URL (or RDF `acl:agent` statement).
   */
  addMailTo (agent) {
    if (typeof agent !== 'string') {
      agent = agent.object.value
    }
    if (agent.startsWith('mailto:')) {
      agent = agent.split(':')[ 1 ]
    }
    this.mailTo.push(agent)
    this.mailTo.sort()
  }

  /**
   * Adds one or more access modes (`acl:mode` statements) to this permission.
   * @method addMode
   * @param accessMode {String|Statement|Array<String>|Array<Statement>} One or
   *   more access modes, each as either a uri, or an RDF statement.
   * @return {Permission} Returns self, chainable.
   */
  addMode (accessMode) {
    if (Array.isArray(accessMode)) {
      accessMode.forEach(ea => {
        this.addModeSingle(ea)
      })
    } else {
      this.addModeSingle(accessMode)
    }
    return this
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
      accessMode = accessMode.object.value
    }
    this.accessModes[ accessMode ] = true
    return this
  }

  /**
   * Adds one or more allowed origins (`acl:origin` statements) to this
   * permission.
   * @method addOrigin
   * @param origin {String|Statement|Array<String>|Array<Statement>} One or
   *   more origins, each as either a uri, or an RDF statement.
   * @return {Permission} Returns self, chainable.
   */
  addOrigin (origin) {
    if (Array.isArray(origin)) {
      origin.forEach((ea) => {
        this.addOriginSingle(ea)
      })
    } else {
      this.addOriginSingle(origin)
    }
    return this
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
      origin = origin.object.value
    }
    this.originsAllowed[ origin ] = true
    return this
  }

  /**
   * Returns a list of all access modes for this permission.
   * @method allModes
   * @return {Array<String>}
   */
  allModes () {
    return Object.keys(this.accessModes)
  }

  /**
   * Returns a list of all allowed origins for this permission.
   * @method allOrigins
   * @return {Array<String>}
   */
  allOrigins () {
    return Object.keys(this.originsAllowed)
  }

  /**
   * Tests whether this permission grant the specified access mode
   * @param accessMode {String|NamedNode} Either a named node for the access
   *   mode or a string key ('write', 'read' etc) that maps to that mode.
   * @return {Boolean}
   */
  allowsMode (accessMode) {
    // Normalize the access mode
    accessMode = acl[accessMode.toUpperCase()] || accessMode
    if (accessMode === acl.APPEND) {
      return this.allowsAppend() // Handle the Append special case
    }
    return this.accessModes[accessMode]
  }
  /**
   * Does this permission grant access to requests coming from given origin?
   * @method allowsOrigin
   * @param origin {String}
   * @return {Boolean}
   */
  allowsOrigin (origin) {
    return origin in this.originsAllowed
  }

  /**
   * Does this permission grant `acl:Read` access mode?
   * @method allowsRead
   * @return {Boolean}
   */
  allowsRead () {
    return this.accessModes[ acl.READ ]
  }

  /**
   * Does this permission grant `acl:Write` access mode?
   * @method allowsWrite
   * @return {Boolean}
   */
  allowsWrite () {
    return this.accessModes[ acl.WRITE ]
  }

  /**
   * Does this permission grant `acl:Append` access mode?
   * @method allowsAppend
   * @return {Boolean}
   */
  allowsAppend () {
    return this.accessModes[ acl.APPEND ] || this.accessModes[ acl.WRITE ]
  }

  /**
   * Does this permission grant `acl:Control` access mode?
   * @method allowsControl
   * @return {Boolean}
   */
  allowsControl () {
    return this.accessModes[ acl.CONTROL ]
  }

  /**
   * Returns a deep copy of this permission.
   * @return {Permission}
   */
  clone () {
    let auth = new Permission()
    Object.assign(auth, JSON.parse(JSON.stringify(this)))
    return auth
  }

  /**
   * Compares this permission with another one.
   * Permissions are equal iff they:
   *   - Are for the same agent or group
   *   - Are intended for the same resourceUrl
   *   - Grant the same access modes
   *   - Have the same `inherit`/`acl:default` flag
   *   - Contain the same `mailto:` agent aliases.
   *   - Has the same allowed origins
   * @method equals
   * @param auth {Permission}
   * @return {Boolean}
   */
  equals (auth) {
    let sameAgent = this.agent === auth.agent
    let sameGroup = this.group === auth.group
    let sameUrl = this.resourceUrl === auth.resourceUrl
    let myModeKeys = Object.keys(this.accessModes)
    let authModeKeys = Object.keys(auth.accessModes)
    let sameNumberModes = myModeKeys.length === authModeKeys.length
    let sameInherit =
      JSON.stringify(this.inherited) === JSON.stringify(auth.inherited)
    let sameModes = true
    myModeKeys.forEach((key) => {
      if (!auth.accessModes[ key ]) { sameModes = false }
    })
    let sameMailTos = JSON.stringify(this.mailTo) === JSON.stringify(auth.mailTo)
    let sameOrigins =
      JSON.stringify(this.originsAllowed) === JSON.stringify(auth.originsAllowed)
    return sameAgent && sameGroup && sameUrl && sameNumberModes && sameModes &&
      sameInherit && sameMailTos && sameOrigins
  }

  /**
   * Returns a hashed combination of agent/group webId and resourceUrl. Used
   * internally as a key to store this permission in a PermissionSet.
   * @method hashFragment
   * @private
   * @throws {Error} Errors if either the webId or the resourceUrl are not set.
   * @return {String} hash({webId}-{resourceUrl})
   */
  hashFragment () {
    if (!this.webId || !this.resourceUrl) {
      throw new Error('Cannot call hashFragment() on an incomplete permission')
    }
    let hashFragment = hashFragmentFor(this.webId(), this.resourceUrl,
      this.accessType)
    return hashFragment
  }

  /**
   * Returns whether or not this permission is for an agent (vs a group).
   * @method isAgent
   * @return {Boolean} Truthy value if agent is set
   */
  isAgent () {
    return this.agent
  }

  /**
   * Returns whether or not this permission is empty (that is, whether it has
   * any access modes like Read, Write, etc, set on it)
   * @method isEmpty
   * @return {Boolean}
   */
  isEmpty () {
    return Object.keys(this.accessModes).length === 0
  }

  /**
   * Is this permission intended for the foaf:Agent group (that is, everyone)?
   * @method isPublic
   * @return {Boolean}
   */
  isPublic () {
    return this.group === acl.EVERYONE
  }

  /**
   * Returns whether or not this permission is for a group (vs an agent).
   * @method isGroup
   * @return {Boolean} Truthy value if group is set
   */
  isGroup () {
    return this.group
  }

  /**
   * Returns whether this permission is for a container and should be inherited
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
   * Returns whether this permission is valid (ready to be serialized into
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
   * Merges the access modes of a given permission with the access modes of
   * this one (Set union).
   * @method mergeWith
   * @param auth
   * @throws {Error} Error if the other permission is for a different webId
   *   or resourceUrl (`acl:accessTo`)
   */
  mergeWith (auth) {
    if (this.hashFragment() !== auth.hashFragment()) {
      throw new Error('Cannot merge permissions with different agent id or resource url (accessTo)')
    }
    for (var accessMode in auth.accessModes) {
      this.addMode(accessMode)
    }
  }

  /**
   * Returns an array of RDF statements representing this permission.
   * Used by `PermissionSet.serialize()`.
   * @method rdfStatements
   * @param rdf {RDF} RDF Library
   * @return {Array<Triple>} List of RDF statements representing this Auth,
   *   or an empty array if this permission is invalid.
   */
  rdfStatements (rdf) {
    // Make sure the permission has at least one agent/group and `accessTo`
    if (!this.webId() || !this.resourceUrl) {
      return [] // This Permission is invalid, return empty array
    }
    // Virtual / implied permissions are not serialized
    if (this.virtual) {
      return []
    }
    let statement
    let fragment = rdf.namedNode('#' + this.hashFragment())
    let ns = vocab(rdf)
    let statements = [
      rdf.triple(
        fragment,
        ns.rdf('type'),
        ns.acl('Authorization'))
    ]
    if (this.isAgent()) {
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
    if (this.isPublic()) {
      statement = rdf.triple(fragment, ns.acl('agentClass'), ns.foaf('Agent'))
      statements.push(statement)
    } else if (this.isGroup()) {
      statement = rdf.triple(fragment, ns.acl('agentGroup'), rdf.namedNode(this.group))
      statements.push(statement)
    }
    statement = rdf.triple(fragment, ns.acl('accessTo'),
      rdf.namedNode(this.resourceUrl))
    statements.push(statement)
    let modes = Object.keys(this.accessModes)
    modes.forEach((accessMode) => {
      statement = rdf.triple(fragment, ns.acl('mode'), rdf.namedNode(accessMode))
      statements.push(statement)
    })
    if (this.inherited) {
      statement = rdf.triple(fragment, ns.acl('default'),
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
   * Removes one or more access modes from this permission.
   * @method removeMode
   * @param accessMode {String|Statement|Array<String>|Array<Statement>} URL
   *   representation of the access mode, or an RDF `acl:mode` triple.
   * @returns {removeMode}
   */
  removeMode (accessMode) {
    if (Array.isArray(accessMode)) {
      accessMode.forEach((ea) => {
        this.removeModeSingle(ea)
      })
    } else {
      this.removeModeSingle(accessMode)
    }
    return this
  }

  /**
   * Removes a single access mode from this permission. Internal use only
   * (used by `removeMode()`).
   * @method removeModeSingle
   * @private
   * @param accessMode {String|Statement} URI or RDF statement
   */
  removeModeSingle (accessMode) {
    if (typeof accessMode !== 'string') {
      accessMode = accessMode.object.value
    }
    delete this.accessModes[ accessMode ]
  }

  /**
   * Removes one or more allowed origins from this permission.
   * @method removeOrigin
   * @param origin {String|Statement|Array<String>|Array<Statement>} URL
   *   representation of the access mode, or an RDF `acl:mode` triple.
   * @returns {removeMode}
   */
  removeOrigin (origin) {
    if (Array.isArray(origin)) {
      origin.forEach((ea) => {
        this.removeOriginSingle(ea)
      })
    } else {
      this.removeOriginSingle(origin)
    }
    return this
  }

  /**
   * Removes a single allowed origin from this permission. Internal use only
   * (used by `removeOrigin()`).
   * @method removeOriginSingle
   * @private
   * @param origin {String|Statement} URI or RDF statement
   */
  removeOriginSingle (origin) {
    if (typeof origin !== 'string') {
      origin = origin.object.value
    }
    delete this.originsAllowed[ origin ]
  }

  /**
   * Sets the agent WebID for this permission.
   * @method setAgent
   * @param agent {string|Quad|GroupListing} Agent URL (or `acl:agent` RDF triple).
   */
  setAgent (agent) {
    if (agent instanceof GroupListing) {
      return this.setGroup(agent)
    }
    if (typeof agent !== 'string') {
      // This is an RDF statement
      agent = agent.object.value
    }
    if (agent === acl.EVERYONE) {
      this.setPublic()
    } else if (this.group) {
      throw new Error('Cannot set agent, permission already has a group set')
    }
    if (agent.startsWith('mailto:')) {
      this.addMailTo(agent)
    } else {
      this.agent = agent
    }
  }

  /**
   * Sets the group WebID for this permission.
   * @method setGroup
   * @param group {string|Triple|GroupListing} Group URL (or `acl:agentClass` RDF
   *   triple).
   */
  setGroup (group) {
    if (this.agent) {
      throw new Error('Cannot set group, permission already has an agent set')
    }
    if (group instanceof GroupListing) {
      group = group.listing
    }
    if (typeof group !== 'string') {
      // This is an RDF statement
      group = group.object.value
    }
    this.group = group
  }

  /**
   * Sets the permission's group to `foaf:Agent`. Convenience method.
   * @method setPublic
   */
  setPublic () {
    this.setGroup(acl.EVERYONE)
  }

  /**
   * Returns the agent or group's WebID for this permission.
   * @method webId
   * @return {String}
   */
  webId () {
    return this.agent || this.group
  }
}
// --- Standalone (non-instance) functions --
/**
 * Utility method that creates a hash fragment key for this permission.
 * Used with graph serialization to RDF, and as a key to store permissions
 * in a PermissionSet. Exported (mainly for use in PermissionSet).
 * @method hashFragmentFor
 * @param webId {String} Agent or group web id
 * @param resourceUrl {String} Resource or container URL for this permission
 * @param [authType='accessTo'] {String} Either 'accessTo' or 'default'
 * @return {String}
 */
function hashFragmentFor (webId, resourceUrl,
  authType = acl.ACCESS_TO) {
  let hashKey = webId + '-' + resourceUrl + '-' + authType
  return hashKey
}

Permission.hashFragmentFor = hashFragmentFor

module.exports = Permission
