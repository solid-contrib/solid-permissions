'use strict'
/**
 * @module permission-set
 * Models the set of Authorizations in a given .acl resource.
 * @see https://github.com/solid/web-access-control-spec for details.
 * The working assumptions here are:
 *   - Model the various permissions in an ACL resource as a set of unique
 *     authorizations, with one agent (or one group), and only
 *     one resource (acl:accessTo or acl:default) per authorization.
 *   - If the source RDF of the ACL resource has multiple agents or multiple
 *     resources in one authorization, separate them into multiple separate
 *     Authorization objects (with one agent/group and one resourceUrl each)
 *   - A single Authorization object can grant access to multiple modes (read,
 *     write, control, etc)
 *   - By default, all the authorizations in a container's ACL will be marked
 *     as 'to be inherited', that is will have `acl:default` set.
 */

const Authorization = require('./authorization')
const GroupListing = require('./group-listing')
const { acl } = require('./modes')
const vocab = require('solid-namespace')
const debug = require('debug')('solid:permissions')

const DEFAULT_ACL_SUFFIX = '.acl'
const DEFAULT_CONTENT_TYPE = 'text/turtle'
/**
 * Resource types, used by PermissionSet objects
 */
const RESOURCE = 'resource'
const CONTAINER = 'container'

/**
 * Agent type index names (used by findAuthByAgent() etc)
 */
const AGENT_INDEX = 'agents'
const GROUP_INDEX = 'groups'

class PermissionSet {
  /**
   * @class PermissionSet
   * @param resourceUrl {String} URL of the resource to which this PS applies
   * @param aclUrl {String} URL of the ACL corresponding to the resource
   * @param isContainer {Boolean} Is the resource a container? (Affects usage of
   *   inherit semantics / acl:default)
   * @param [options={}] {Object} Options hashmap
   * @param [options.graph] {Graph} Parsed RDF graph of the ACL resource
   * @param [options.rdf] {RDF} RDF Library
   * @param [options.strictOrigin] {Boolean} Enforce strict origin?
   * @param [options.host] {String} Actual request uri
   * @param [options.origin] {String} Origin URI to enforce, relevant
   *   if strictOrigin is set to true
   * @param [options.webClient] {SolidWebClient} Used for save() and clear()
   * @param [options.isAcl] {Function}
   * @param [options.aclUrlFor] {Function}
   * @constructor
   */
  constructor (resourceUrl, aclUrl, isContainer, options = {}) {
    /**
     * Hashmap of all Authorizations in this permission set, keyed by a hashed
     * combination of an agent's/group's webId and the resourceUrl.
     * @property authorizations
     * @type {Object}
     */
    this.authorizations = {}
    /**
     * The URL of the corresponding ACL resource, at which these permissions will
     * be saved.
     * @property aclUrl
     * @type {String}
     */
    this.aclUrl = aclUrl
    /**
     * Optional request host (used by checkOrigin())
     * @property host
     * @type {String}
     */
    this.host = options.host
    /**
     * Initialize the agents / groups indexes.
     * For each index type (`agents`, `groups`), authorizations are indexed
     * first by `agentId`, then by access type (direct or inherited), and
     * lastly by resource. For example:
     *
     *   ```
     *   agents: {
     *     'https://alice.com/#i': {
     *       accessTo: {
     *         'https://alice.com/file1': authorization1
     *       },
     *       default: {
     *         'https://alice.com/': authorization2
     *       }
     *     }
     *   }
     *   ```
     * @property authsBy
     * @type {Object}
     */
    this.authsBy = {
      'agents': {}, // Auths by agent webId
      'groups': {} // Auths by group webId (also includes Public / EVERYONE)
    }
    /**
     * Cache of GroupListing objects, by group webId. Populated by `loadGroups()`.
     * @property groups
     * @type {Object}
     */
    this.groups = {}
    /**
     * RDF Library (optionally injected)
     * @property rdf
     * @type {RDF}
     */
    this.rdf = options.rdf
    /**
     * Whether this permission set is for a 'container' or a 'resource'.
     * Determines whether or not the inherit/'acl:default' attribute is set on
     * all its Authorizations.
     * @property resourceType
     * @type {String}
     */
    this.resourceType = isContainer ? CONTAINER : RESOURCE
    /**
     * The URL of the resource for which these permissions apply.
     * @property resourceUrl
     * @type {String}
     */
    this.resourceUrl = resourceUrl
    /**
     * Should this permission set enforce "strict origin" policy?
     * (If true, uses `options.origin` parameter)
     * @property strictOrigin
     * @type {Boolean}
     */
    this.strictOrigin = options.strictOrigin
    /**
     * Contents of the request's `Origin:` header.
     * (used only if `strictOrigin` parameter is set to true)
     * @property origin
     * @type {String}
     */
    this.origin = options.origin
    /**
     * Solid REST client (optionally injected), used by save() and clear().
     * @type {SolidWebClient}
     */
    this.webClient = options.webClient

    // Init the functions for deriving an ACL url for a given resource
    this.aclUrlFor = options.aclUrlFor ? options.aclUrlFor : defaultAclUrlFor
    this.aclUrlFor.bind(this)
    this.isAcl = options.isAcl ? options.isAcl : defaultIsAcl
    this.isAcl.bind(this)

    // Optionally initialize from a given parsed graph
    if (options.graph) {
      this.initFromGraph(options.graph)
    }
  }

  /**
   * Adds a given Authorization instance to the permission set.
   * Low-level function, clients should use `addPermission()` instead, in most
   * cases.
   * @method addAuthorization
   * @private
   * @param auth {Authorization}
   * @return {PermissionSet} Returns self (chainable)
   */
  addAuthorization (auth) {
    var hashFragment = auth.hashFragment()
    if (hashFragment in this.authorizations) {
      // An authorization for this agent and resource combination already exists
      // Merge the incoming access modes with its existing ones
      this.authorizations[hashFragment].mergeWith(auth)
    } else {
      this.authorizations[hashFragment] = auth
    }
    if (!auth.virtual && auth.allowsControl()) {
      // If acl:Control is involved, ensure implicit rules for the .acl resource
      this.addControlPermissionsFor(auth)
    }
    // Create the appropriate indexes
    this.addToAgentIndex(auth)
    if (auth.isPublic() || auth.isGroup()) {
      this.addToGroupIndex(auth)
    }
    return this
  }

  /**
   * Creates an Authorization with the given parameters, and passes it on to
   * `addAuthorization()` to be added to this PermissionSet.
   * Essentially a convenience factory method.
   * @method addAuthorizationFor
   * @private
   * @param resourceUrl {String}
   * @param inherit {Boolean}
   * @param agent {string|Quad|GroupListing} Agent URL (or `acl:agent` RDF triple).
   * @param [accessModes=[]] {string|NamedNode|Array} 'READ'/'WRITE' etc.
   * @param [origins=[]] {Array<String>} List of origins that are allowed access
   * @param [mailTos=[]] {Array<String>}
   * @return {PermissionSet} Returns self, chainable
   */
  addAuthorizationFor (resourceUrl, inherit, agent, accessModes = [],
    origins = [], mailTos = []) {
    let auth = new Authorization(resourceUrl, inherit)
    if (agent instanceof GroupListing) {
      auth.setGroup(agent.listing)
    } else {
      auth.setAgent(agent)
    }
    auth.addMode(accessModes)
    auth.addOrigin(origins)
    mailTos.forEach(mailTo => {
      auth.addMailTo(mailTo)
    })
    this.addAuthorization(auth)
    return this
  }

  /**
   * Adds a virtual (will not be serialized to RDF) authorization giving
   * Read/Write/Control access to the corresponding ACL resource if acl:Control
   * is encountered in the actual source ACL.
   * @method addControlPermissionsFor
   * @private
   * @param auth {Authorization} Authorization containing an acl:Control access
   *   mode.
   */
  addControlPermissionsFor (auth) {
    let impliedAuth = auth.clone()
    impliedAuth.resourceUrl = this.aclUrlFor(auth.resourceUrl)
    impliedAuth.virtual = true
    impliedAuth.addMode(acl.ALL_MODES)
    this.addAuthorization(impliedAuth)
  }

  /**
   * Adds a group permission for the given access mode and group web id.
   * @method addGroupPermission
   * @param webId {String}
   * @param accessMode {String|Array<String>}
   * @return {PermissionSet} Returns self (chainable)
   */
  addGroupPermission (webId, accessMode) {
    if (!this.resourceUrl) {
      throw new Error('Cannot add a permission to a PermissionSet with no resourceUrl')
    }
    var auth = new Authorization(this.resourceUrl, this.isAuthInherited())
    auth.setGroup(webId)
    auth.addMode(accessMode)
    this.addAuthorization(auth)
    return this
  }

  /**
   * Adds a permission for the given access mode and agent id.
   * @method addPermission
   * @param webId {String} URL of an agent for which this permission applies
   * @param accessMode {String|Array<String>} One or more access modes
   * @param [origin] {String|Array<String>} One or more allowed origins (optional)
   * @return {PermissionSet} Returns self (chainable)
   */
  addPermission (webId, accessMode, origin) {
    if (!webId) {
      throw new Error('addPermission() requires a valid webId')
    }
    if (!accessMode) {
      throw new Error('addPermission() requires a valid accessMode')
    }
    if (!this.resourceUrl) {
      throw new Error('Cannot add a permission to a PermissionSet with no resourceUrl')
    }
    var auth = new Authorization(this.resourceUrl, this.isAuthInherited())
    auth.setAgent(webId)
    auth.addMode(accessMode)
    if (origin) {
      auth.addOrigin(origin)
    }
    this.addAuthorization(auth)
    return this
  }

  /**
   * Adds a given authorization to the "lookup by agent id" index.
   * Enables lookups via `findAuthByAgent()`.
   * @method addToAgentIndex
   * @private
   * @param authorization {Authorization}
   */
  addToAgentIndex (authorization) {
    let webId = authorization.webId()
    let accessType = authorization.accessType
    let resourceUrl = authorization.resourceUrl
    let agents = this.authsBy.agents
    if (!agents[webId]) {
      agents[webId] = {}
    }
    if (!agents[webId][accessType]) {
      agents[webId][accessType] = {}
    }
    if (!agents[webId][accessType][resourceUrl]) {
      agents[webId][accessType][resourceUrl] = authorization
    } else {
      agents[webId][accessType][resourceUrl].mergeWith(authorization)
    }
  }

  /**
   * Adds a given authorization to the "lookup by group id" index.
   * Enables lookups via `findAuthByAgent()`.
   * @method addToGroupIndex
   * @private
   * @param authorization {Authorization}
   */
  addToGroupIndex (authorization) {
    let webId = authorization.webId()
    let accessType = authorization.accessType
    let resourceUrl = authorization.resourceUrl
    let groups = this.authsBy.groups
    if (!groups[webId]) {
      groups[webId] = {}
    }
    if (!groups[webId][accessType]) {
      groups[webId][accessType] = {}
    }
    if (!groups[webId][accessType][resourceUrl]) {
      groups[webId][accessType][resourceUrl] = authorization
    } else {
      groups[webId][accessType][resourceUrl].mergeWith(authorization)
    }
  }

  /**
   * Returns a list of all the Authorizations that belong to this permission set.
   * Mostly for internal use.
   * @method allAuthorizations
   * @return {Array<Authorization>}
   */
  allAuthorizations () {
    var authList = []
    var auth
    Object.keys(this.authorizations).forEach(authKey => {
      auth = this.authorizations[authKey]
      authList.push(auth)
    })
    return authList
  }

  /**
   * Tests whether this PermissionSet gives Public (acl:agentClass foaf:Agent)
   * access to a given uri.
   * @method allowsPublic
   * @param mode {String|NamedNode} Access mode (read/write/control etc)
   * @param resourceUrl {String}
   * @return {Boolean}
   */
  allowsPublic (mode, resourceUrl) {
    resourceUrl = resourceUrl || this.resourceUrl
    let publicAuth = this.findPublicAuth(resourceUrl)
    if (!publicAuth) {
      return false
    }
    return publicAuth.allowsMode(mode)
  }

  /**
   * Returns an RDF graph representation of this permission set and all its
   * Authorizations. Used by `save()`.
   * @method buildGraph
   * @private
   * @param rdf {RDF} RDF Library
   * @return {Graph}
   */
  buildGraph (rdf) {
    var graph = rdf.graph()
    this.allAuthorizations().forEach(function (auth) {
      graph.add(auth.rdfStatements(rdf))
    })
    return graph
  }

  /**
   * Tests whether the given agent has the specified access to a resource.
   * This is one of the main use cases for this solid-permissions library.
   * Optionally performs strict origin checking (if `strictOrigin` is enabled
   * in the constructor's options).
   * @method checkAccess
   * @param resourceUrl {String}
   * @param agentId {String}
   * @param accessMode {String} Access mode (read/write/control)
   * @param [options={}] {Object} Passed through to `loadGroups()`.
   * @param [options.fetchGraph] {Function} Injected, returns a parsed graph of
   *   a remote document (group listing). Required.
   * @param [options.rdf] {RDF} RDF library
   * @throws {Error}
   * @return {Promise<Boolean>}
   */
  checkAccess (resourceUrl, agentId, accessMode, options = {}) {
    debug('Checking access for agent ' + agentId)
    // First, check to see if there is public access for this mode
    if (this.allowsPublic(accessMode, resourceUrl)) {
      debug('Public access allowed for ' + resourceUrl)
      return Promise.resolve(true)
    }
    // Next, see if there is an individual authorization (for a user or a group)
    if (this.checkAccessForAgent(resourceUrl, agentId, accessMode)) {
      debug('Individual access granted for ' + resourceUrl)
      return Promise.resolve(true)
    }

    if (this.hasGroups()) {
      // Lastly, load the remote group listings, and check for group auth
      debug('Check groups authorizations')

      return this.loadGroups(options)
	    .then(() => {
		return this.checkGroupAccess(resourceUrl, agentId, accessMode, options)
	    })
    }

    // Then, access will not be granted
    debug('Can agent ' + agentId + ' ' + accessMode + ' ' + resourceUrl + '?')
    if (this.origin) {
      debug('Can origin ' + this.origin + ' ' + accessMode + ' ' + resourceUrl + '?')
    }
    return Promise.resolve(false);
  }

  /**
   * @param resourceUrl {String}
   * @param agentId {String}
   * @param accessMode {String} Access mode (read/write/control)
   * @throws {Error}
   * @return {Boolean}
   */
  checkAccessForAgent (resourceUrl, agentId, accessMode) {
    let auth = this.findAuthByAgent(agentId, resourceUrl)
    let result = auth && this.checkOrigin(auth) && auth.allowsMode(accessMode)
    return result
  }

  /**
   * @param resourceUrl {string}
   * @param agentId {string}
   * @param accessMode {string} Access mode (read/write/control)
   * @param [options={}] {Object}
   * @param [options.fetchDocument] {Function}
   * @throws {Error}
   * @return {boolean}
   */
  checkGroupAccess (resourceUrl, agentId, accessMode, options = {}) {
    let result = false
    let membershipMatches = this.groupsForMember(agentId)
    membershipMatches.find(groupWebId => {
      debug('Looking for access rights for ' + groupWebId)
      if (this.checkAccessForAgent(resourceUrl, groupWebId, accessMode)) {
        debug('Groups access granted for ' + resourceUrl)
        result = true
      }
    })
    return result
  }

  /**
   * Tests whether a given authorization allows operations from the current
   * request's `Origin` header. (The current request's origin and host are
   * passed in as options to the PermissionSet's constructor.)
   * @param authorization {Authorization}
   * @return {Boolean}
   */
  checkOrigin (authorization) {
    if (!this.strictOrigin || // Enforcement turned off in server config
        !this.origin || // No origin - not a script, do not enforce origin
        this.origin === this.host) { // same origin is trusted
      return true
    }
    debug('Not the same origin, checking ACL')
    // If not same origin, check that the origin is in the explicit ACL list
    return authorization.allowsOrigin(this.origin)
  }

  /**
   * Sends a delete request to a particular ACL resource. Intended to be used for
   * an existing loaded PermissionSet, but you can also specify a particular
   * URL to delete.
   * Usage:
   *
   *   ```
   *   // If you have an existing PermissionSet as a result of `getPermissions()`:
   *   solid.getPermissions('https://www.example.com/file1')
   *     .then(function (permissionSet) {
   *       // do stuff
   *       return permissionSet.clear()  // deletes that permissionSet
   *     })
   *   // Otherwise, use the helper function
   *   //   solid.clearPermissions(resourceUrl) instead
   *   solid.clearPermissions('https://www.example.com/file1')
   *     .then(function (response) {
   *       // file1.acl is now deleted
   *     })
   *   ```
   * @method clear
   * @param [webClient] {SolidWebClient}
   * @throws {Error} Rejects with an error if it doesn't know where to delete, or
   *   with any XHR errors that crop up.
   * @return {Promise<Request>}
   */
  clear (webClient) {
    webClient = webClient || this.webClient
    if (!webClient) {
      return Promise.reject(new Error('Cannot clear - no web client'))
    }
    var aclUrl = this.aclUrl
    if (!aclUrl) {
      return Promise.reject(new Error('Cannot clear - unknown target url'))
    }
    return webClient.del(aclUrl)
  }

  /**
   * Returns the number of Authorizations in this permission set.
   * @method count
   * @return {Number}
   */
  get count () {
    return Object.keys(this.authorizations).length
  }

  /**
   * Returns whether or not this permission set is equal to another one.
   * A PermissionSet is considered equal to another one iff:
   * - It has the same number of authorizations, and each of those authorizations
   *   has a corresponding one in the other set
   * - They are both intended for the same resource (have the same resourceUrl)
   * - They are both intended to be saved at the same aclUrl
   * @method equals
   * @param ps {PermissionSet} The other permission set to compare to
   * @return {Boolean}
   */
  equals (ps) {
    var sameUrl = this.resourceUrl === ps.resourceUrl
    var sameAclUrl = this.aclUrl === ps.aclUrl
    var sameResourceType = this.resourceType === ps.resourceType
    var myAuthKeys = Object.keys(this.authorizations)
    var otherAuthKeys = Object.keys(ps.authorizations)
    if (myAuthKeys.length !== otherAuthKeys.length) { return false }
    var sameAuths = true
    var myAuth, otherAuth
    myAuthKeys.forEach(authKey => {
      myAuth = this.authorizations[authKey]
      otherAuth = ps.authorizations[authKey]
      if (!otherAuth) {
        sameAuths = false
      }
      if (!myAuth.equals(otherAuth)) {
        sameAuths = false
      }
    })
    return sameUrl && sameAclUrl && sameResourceType && sameAuths
  }

  /**
   * Finds and returns an authorization (stored in the 'find by agent' index)
   * for a given agent (web id) and resource.
   * @method findAuthByAgent
   * @private
   * @param webId {String}
   * @param resourceUrl {String}
   * @param indexType {String} Either 'default' or 'accessTo'
   * @return {Authorization}
   */
  findAuthByAgent (webId, resourceUrl, indexType = AGENT_INDEX) {
    let index = this.authsBy[indexType]
    if (!index[webId]) {
      // There are no permissions at all for this agent
      return false
    }
    // first check the accessTo type
    let accessToAuths = index[webId][acl.ACCESS_TO]
    let accessToMatch
    if (accessToAuths) {
      accessToMatch = accessToAuths[resourceUrl]
    }
    if (accessToMatch) {
      return accessToMatch
    }
    // then check the default/inherited type permissions
    let defaultAuths = index[webId][acl.DEFAULT]
    let defaultMatch
    if (defaultAuths) {
      // First try an exact match (resource matches the acl:default object)
      defaultMatch = defaultAuths[resourceUrl]
      if (!defaultMatch) {
        // Next check to see if resource is in any of the relevant containers
        let containers = Object.keys(defaultAuths).sort().reverse()
        // Loop through the container URLs, sorted in reverse alpha
        for (let containerUrl of containers) {
          if (resourceUrl.startsWith(containerUrl)) {
            defaultMatch = defaultAuths[containerUrl]
            break
          }
        }
      }
    }
    return defaultMatch
  }

  /**
   * Finds and returns an authorization (stored in the 'find by group' index)
   * for the "Everyone" group (acl:agentClass foaf:Agent), for a given resource.
   * @method findAuthByAgent
   * @private
   * @param resourceUrl {String}
   * @return {Authorization}
   */
  findPublicAuth (resourceUrl) {
    return this.findAuthByAgent(acl.EVERYONE, resourceUrl, GROUP_INDEX)
  }

  /**
   * Iterates over all the authorizations in this permission set.
   * Convenience method.
   * Usage:
   *
   *   ```
   *   solid.getPermissions(resourceUrl)
   *     .then(function (permissionSet) {
   *       permissionSet.forEach(function (auth) {
   *         // do stuff with auth
   *       })
   *     })
   *   ```
   * @method forEach
   * @param callback {Function} Function to apply to each authorization
   */
  forEach (callback) {
    this.allAuthorizations().forEach(auth => {
      callback.call(this, auth)
    })
  }

  /**
   * Returns a list of webIds of groups to which this agent belongs.
   * Note: Only checks loaded groups (assumes a previous `loadGroups()` call).
   * @param agentId {string}
   * @return {Array<string>}
   */
  groupsForMember (agentId) {
    let loadedGroupIds = Object.keys(this.groups)
    return loadedGroupIds
      .filter(groupWebId => {
        return this.groups[groupWebId].hasMember(agentId)
      })
  }

  /**
   * Returns a list of URIs of group authorizations in this permission set
   * (those added via addGroupPermission(), etc).
   * @param [excludePublic=true] {Boolean} Should agentClass Agent be excluded?
   * @return {Array<string>}
   */
  groupUris (excludePublic = true) {
    let groupIndex = this.authsBy.groups
    let uris = Object.keys(groupIndex)
    if (excludePublic) {
      uris = uris.filter((uri) => { return uri !== acl.EVERYONE })
    }
    return uris
  }

  /**
   * Tests whether this permission set has any `acl:agentGroup` authorizations
   * @return {Boolean}
   */
  hasGroups () {
    return this.groupUris().length > 0
  }

  /**
   * Creates and loads all the authorizations from a given RDF graph.
   * Used by `getPermissions()` and by the constructor (optionally).
   * Usage:
   *
   *   ```
   *   var acls = new PermissionSet(resourceUri, aclUri, isContainer, {rdf: rdf})
   *   acls.initFromGraph(graph)
   *   ```
   * @method initFromGraph
   * @param graph {Dataset} RDF Graph (parsed from the source ACL)
   */
  initFromGraph (graph) {
    let ns = vocab(this.rdf)
    let authSections = graph.match(null, null, ns.acl('Authorization'))
    if (authSections.length) {
      authSections = authSections.map(match => { return match.subject })
    } else {
      // Attempt to deal with an ACL with no acl:Authorization types present.
      let subjects = {}
      authSections = graph.match(null, ns.acl('mode'))
      authSections.forEach(match => {
        subjects[match.subject.value] = match.subject
      })
      authSections = Object.keys(subjects).map(section => {
        return subjects[section]
      })
    }
    // Iterate through each grouping of authorizations in the .acl graph
    authSections.forEach(fragment => {
      // Extract the access modes
      let accessModes = graph.match(fragment, ns.acl('mode'))
      // Extract allowed origins
      let origins = graph.match(fragment, ns.acl('origin'))

      // Extract all the authorized agents
      let agentMatches = graph.match(fragment, ns.acl('agent'))
      // Mailtos only apply to agents (not groups)
      let mailTos = agentMatches.filter(isMailTo)
      // Now filter out mailtos
      agentMatches = agentMatches.filter(ea => { return !isMailTo(ea) })
      // Extract all 'Public' matches (agentClass foaf:Agent)
      let publicMatches = graph.match(fragment, ns.acl('agentClass'),
        ns.foaf('Agent'))
      // Extract all acl:agentGroup matches
      let groupMatches = graph.match(fragment, ns.acl('agentGroup'))
      groupMatches = groupMatches.map(ea => {
        return new GroupListing({ listing: ea })
      })
      // Create an Authorization object for each group (accessTo and default)
      let allAgents = agentMatches
        .concat(publicMatches)
        .concat(groupMatches)
      // Create an Authorization object for each agent or group
      //   (both individual (acl:accessTo) and inherited (acl:default))
      allAgents.forEach(agentMatch => {
        // Extract the acl:accessTo statements.
        let accessToMatches = graph.match(fragment, ns.acl('accessTo'))
        accessToMatches.forEach(resourceMatch => {
          let resourceUrl = resourceMatch.object.value
          this.addAuthorizationFor(resourceUrl, acl.NOT_INHERIT,
            agentMatch, accessModes, origins, mailTos)
        })
        // Extract inherited / acl:default statements
        let inheritedMatches = graph.match(fragment, ns.acl('default'))
          .concat(graph.match(fragment, ns.acl('defaultForNew')))
        inheritedMatches.forEach(containerMatch => {
          let containerUrl = containerMatch.object.value
          this.addAuthorizationFor(containerUrl, acl.INHERIT,
            agentMatch, accessModes, origins, mailTos)
        })
      })
    })
  }

  /**
   * Returns whether or not authorizations added to this permission set be
   * inherited, by default? (That is, should they have acl:default set on them).
   * @method isAuthInherited
   * @return {Boolean}
   */
  isAuthInherited () {
    return this.resourceType === CONTAINER
  }

  /**
   * Returns whether or not this permission set has any Authorizations added to it
   * @method isEmpty
   * @return {Boolean}
   */
  isEmpty () {
    return this.count === 0
  }

  /**
   * @method loadGroups
   * @param [options={}]
   * @param [options.fetchGraph] {Function} Injected, returns a parsed graph of
   *   a remote document (group listing). Required.
   * @param [options.rdf] {RDF} RDF library
   * @throws {Error}
   * @return {Promise<PermissionSet>} Resolves to self, chainable
   */
  loadGroups (options = {}) {
    let fetchGraph = options.fetchGraph
    debug('Fetching with ' + fetchGraph)
    let rdf = options.rdf || this.rdf
    if (!fetchGraph) {
      return Promise.reject(new Error('Cannot load groups, fetchGraph() not supplied'))
    }
    if (!rdf) {
      return Promise.reject(new Error('Cannot load groups, rdf library not supplied'))
    }
    let uris = this.groupUris()
    let loadActions = uris.map(uri => {
      return GroupListing.loadFrom(uri, fetchGraph, rdf, options)
    })
    return Promise.all(loadActions)
      .then(groups => {
        groups.forEach(group => {
          if (group) { this.groups[group.uri] = group }
        })
        return this
      })
  }

  /**
   * Returns the corresponding Authorization for a given agent/group webId (and
   * for a given resourceUrl, although it assumes by default that it's the same
   * resourceUrl as the PermissionSet).
   * @method permissionFor
   * @param webId {String} URL of the agent or group
   * @param [resourceUrl] {String}
   * @return {Authorization} Returns the corresponding Authorization, or `null`
   *   if no webId is given, or if no such authorization exists.
   */
  permissionFor (webId, resourceUrl) {
    if (!webId) {
      return null
    }
    resourceUrl = resourceUrl || this.resourceUrl
    var hashFragment = Authorization.hashFragmentFor(webId, resourceUrl)
    return this.authorizations[hashFragment]
  }

  /**
   * Deletes a given Authorization instance from the permission set.
   * Low-level function, clients should use `removePermission()` instead, in most
   * cases.
   * @method removeAuthorization
   * @param auth {Authorization}
   * @return {PermissionSet} Returns self (chainable)
   */
  removeAuthorization (auth) {
    var hashFragment = auth.hashFragment()
    delete this.authorizations[hashFragment]
    return this
  }

  /**
   * Removes one or more access modes from an authorization in this permission set
   * (defined by a unique combination of agent/group id (webId) and a resourceUrl).
   * If no more access modes remain for that authorization, it's deleted from the
   * permission set.
   * @method removePermission
   * @param webId
   * @param accessMode {String|Array<String>}
   * @return {PermissionSet} Returns self (via a chainable function)
   */
  removePermission (webId, accessMode) {
    var auth = this.permissionFor(webId, this.resourceUrl)
    if (!auth) {
      // No authorization for this webId + resourceUrl exists. Bail.
      return this
    }
    // Authorization exists, remove the accessMode from it
    auth.removeMode(accessMode)
    if (auth.isEmpty()) {
      // If no more access modes remain, after removing, delete it from this
      // permission set
      this.removeAuthorization(auth)
    }
    return this
  }

  /**
   * @method save
   * @param [options={}] {Object} Options hashmap
   * @param [options.aclUrl] {String} Optional URL to save the .ACL resource to.
   *   Defaults to its pre-set `aclUrl`, if not explicitly passed in.
   * @param [options.contentType] {string} Optional content type to serialize as
   * @throws {Error} Rejects with an error if it doesn't know where to save, or
   *   with any XHR errors that crop up.
   * @return {Promise<SolidResponse>}
   */
  save (options = {}) {
    let aclUrl = options.aclUrl || this.aclUrl
    let contentType = options.contentType || DEFAULT_CONTENT_TYPE
    if (!aclUrl) {
      return Promise.reject(new Error('Cannot save - unknown target url'))
    }
    if (!this.webClient) {
      return Promise.reject(new Error('Cannot save - no web client'))
    }
    return this.serialize({ contentType })
      .then(graph => {
        return this.webClient.put(aclUrl, graph, contentType)
      })
  }

  /**
   * Serializes this permission set (and all its Authorizations) to a string RDF
   * representation (Turtle by default).
   * Note: invalid authorizations (ones that don't have at least one agent/group,
   * at least one resourceUrl and at least one access mode) do not get serialized,
   * and are instead skipped.
   * @method serialize
   * @param [options={}] {Object} Options hashmap
   * @param [options.contentType='text/turtle'] {string}
   * @param [options.rdf] {RDF} RDF Library to serialize with
   * @throws {Error} Rejects with an error if one is encountered during RDF
   *   serialization.
   * @return {Promise<String>} Graph serialized to contentType RDF syntax
   */
  serialize (options = {}) {
    let contentType = options.contentType || DEFAULT_CONTENT_TYPE
    let rdf = options.rdf || this.rdf
    if (!rdf) {
      return Promise.reject(new Error('Cannot save - no rdf library'))
    }
    let graph = this.buildGraph(rdf)
    let target = null
    let base = this.aclUrl
    return new Promise((resolve, reject) => {
      rdf.serialize(target, graph, base, contentType, (err, result) => {
        if (err) { return reject(err) }
        if (!result) {
          return reject(new Error('Error serializing the graph to ' +
            contentType))
        }
        resolve(result)
      })
    })
  }
}

/**
 * Returns the corresponding ACL uri, for a given resource.
 * This is the default template for the `aclUrlFor()` method that's used by
 * PermissionSet instances, unless it's overridden in options.
 * @param resourceUri {String}
 * @return {String} ACL uri
 */
function defaultAclUrlFor (resourceUri) {
  if (defaultIsAcl(resourceUri)) {
    return resourceUri // .acl resources are their own ACLs
  } else {
    return resourceUri + DEFAULT_ACL_SUFFIX
  }
}

/**
 * Tests whether a given uri is for an ACL resource.
 * This is the default template for the `isAcl()` method that's used by
 * PermissionSet instances, unless it's overridden in options.
 * @method defaultIsAcl
 * @param uri {String}
 * @return {Boolean}
 */
function defaultIsAcl (uri) {
  return uri.endsWith(DEFAULT_ACL_SUFFIX)
}

/**
 * Returns whether or not a given agent webId is actually a `mailto:` link.
 * Standalone helper function.
 * @param agent {String|Statement} URL string (or RDF `acl:agent` triple)
 * @return {Boolean}
 */
function isMailTo (agent) {
  if (typeof agent === 'string') {
    return agent.startsWith('mailto:')
  } else {
    return agent.object.value.startsWith('mailto:')
  }
}

PermissionSet.RESOURCE = RESOURCE
PermissionSet.CONTAINER = CONTAINER
module.exports = PermissionSet
