'use strict'
/**
 * @module permission-set
 * Models the set of Authorizations in a given .acl resource.
 * @see https://github.com/solid/web-access-control-spec for details.
 * The working assumptions here are:
 *   - Model the various permissions in an ACL resource as a set of unique
 *     authorizations, with one agent (or one group), and only
 *     one resource (acl:accessTo) per authorization.
 *   - If the source RDF of the ACL resource has multiple agents or multiple
 *     resources in one authorization, separate them into multiple separate
 *     Authorization objects (with one agent/group and one resourceUrl each)
 *   - A single Authorization object can grant access to multiple modes (read,
 *     write, control, etc)
 *   - By default, all the authorizations in a container's ACL will be marked
 *     as 'to be inherited', that is will have `acl:default` set.
 */

var Authorization = require('./authorization')
var acl = Authorization.acl
var ns = require('solid-namespace')

/**
 * Resource types, used by PermissionSet objects
 * @type {String}
 */
var RESOURCE = 'resource'
var CONTAINER = 'container'

/**
 * @class PermissionSet
 * @param resourceUrl
 * @param aclUrl
 * @param isContainer
 * @param [options={}] {Object} Options hashmap
 * @param [options.graph] {Graph} Parsed RDF graph of the ACL resource
 * @param [options.rdf] {RDF} RDF Library
 * @param [options.strictOrigin] {Boolean} Enforce strict origin?
 * @param [options.host] {String} Actual request uri
 * @param [options.origin] {String} Origin URI to enforce, relevant
 *   if strictOrigin is set to true
 * @param [options.webClient] {SolidWebClient} Used for save() and clear()
 * @constructor
 */
class PermissionSet {
  constructor (resourceUrl, aclUrl, isContainer, options) {
    options = options || {}
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
   * @param auth {Authorization}
   * @return {PermissionSet} Returns self (chainable)
   */
  addAuthorization (auth) {
    var hashFragment = auth.hashFragment()
    if (hashFragment in this.authorizations) {
      // An authorization for this agent and resource combination already exists
      // Merge the incoming access modes with its existing ones
      this.authorizations[ hashFragment ].mergeWith(auth)
    } else {
      this.authorizations[ hashFragment ] = auth
    }
    return this
  }

  /**
   * Adds an agentClass/group permission for the given access mode and agent id.
   * @method addGroupPermission
   * @param webId {String}
   * @param accessMode {String|Array<String>}
   * @return {PermissionSet} Returns self (chainable)
   */
  addGroupPermission (webId, accessMode) {
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
   * Returns a list of all the Authorizations that belong to this permission set.
   * Mostly for internal use.
   * @method allAuthorizations
   * @return {Array<Authorization>}
   */
  allAuthorizations () {
    var authList = []
    var auth
    var self = this
    Object.keys(this.authorizations).forEach(function (authKey) {
      auth = self.authorizations[ authKey ]
      authList.push(auth)
    })
    return authList
  }

  allowsPublic (mode, url) {
    url = url || this.resourceUrl
    var publicAuth = this.permissionFor(acl.EVERYONE, url)
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
  count () {
    return Object.keys(this.authorizations).length
  }

  /**
   * Tests whether the permission set should enforce a strict origin for the
   * request.
   * @method enforceOrigin
   * @return {Boolean}
   */
  enforceOrigin () {
    return this.strictOrigin && this.origin
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
    var self = this
    var sameUrl = this.resourceUrl === ps.resourceUrl
    var sameAclUrl = this.aclUrl === ps.aclUrl
    var sameResourceType = this.resourceType === ps.resourceType
    var myAuthKeys = Object.keys(this.authorizations)
    var otherAuthKeys = Object.keys(ps.authorizations)
    if (myAuthKeys.length !== otherAuthKeys.length) { return false }
    var sameAuths = true
    var myAuth, otherAuth
    myAuthKeys.forEach(function (authKey) {
      myAuth = self.authorizations[ authKey ]
      otherAuth = ps.authorizations[ authKey ]
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
    var self = this
    this.allAuthorizations().forEach(function (auth) {
      callback.call(self, auth)
    })
  }

  /**
   * Creates and loads all the authorizations from a given RDF graph.
   * Used by `getPermissions()`.
   * Usage:
   *
   *   ```
   *   var acls = new PermissionSet(resourceUri, aclUri, isContainer, rdf)
   *   acls.initFromGraph(graph)
   *   ```
   * @method initFromGraph
   * @param graph {Graph} RDF Graph (parsed from the source ACL)
   * @param [rdf] {RDF} Optional RDF Library (needs to be either passed in here,
   *   or in the constructor)
   */
  initFromGraph (graph, rdf) {
    rdf = rdf || this.rdf
    var vocab = ns(rdf)
    var authSections = graph.match(null, null, vocab.acl('Authorization'))
    var agentMatches, mailTos, groupMatches, resourceUrls, auth
    var accessModes, origins, inherit
    var self = this
    if (authSections.length) {
      authSections = authSections.map(function (st) { return st.subject })
    } else {
      // Attempt to deal with an ACL with no acl:Authorization types present.
      var subjects = {}
      authSections = graph.match(null, vocab.acl('mode'))
      authSections.forEach(function (match) {
        subjects[ match.subject.value ] = true
      })
      authSections = Object.keys(subjects)
    }
    // Iterate through each grouping of authorizations in the .acl graph
    authSections.forEach(function (fragment) {
      // Extract all the authorized agents/groups (acl:agent and acl:agentClass)
      agentMatches = graph.match(fragment, vocab.acl('agent'))
      mailTos = agentMatches.filter(isMailTo)
      // Now filter out mailtos
      agentMatches = agentMatches.filter(function (ea) { return !isMailTo(ea) })
      groupMatches = graph.match(fragment, vocab.acl('agentClass'))
      // Extract the acl:accessTo statements. (Have to support multiple ones)
      resourceUrls = graph.match(fragment, vocab.acl('accessTo'))
      // Extract the access modes
      accessModes = graph.match(fragment, vocab.acl('mode'))
      // Extract allowed origins
      origins = graph.match(fragment, vocab.acl('origin'))
      // Check if these permissions are to be inherited
      inherit = graph.match(fragment, vocab.acl('defaultForNew')).length ||
        graph.match(fragment, vocab.acl('default')).length
      // Create an Authorization object for each agent or group
      //   (and for each resourceUrl (acl:accessTo))
      agentMatches.forEach(function (agentMatch) {
        resourceUrls.forEach(function (resourceUrl) {
          auth = new Authorization(resourceUrl.object.uri, inherit)
          auth.setAgent(agentMatch)
          auth.addMode(accessModes)
          auth.addOrigin(origins)
          mailTos.forEach(function (mailTo) {
            auth.addMailTo(mailTo)
          })
          self.addAuthorization(auth)
        })
      })
      groupMatches.forEach(function (groupMatch) {
        resourceUrls.forEach(function (resourceUrl) {
          auth = new Authorization(resourceUrl.object.uri, inherit)
          auth.setGroup(groupMatch)
          auth.addMode(accessModes)
          auth.addOrigin(origins)
          self.addAuthorization(auth)
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
    return this.count() === 0
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
    return this.authorizations[ hashFragment ]
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
    delete this.authorizations[ hashFragment ]
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
   * @param [aclUrl] {String} Optional URL to save the .ACL resource to. Defaults
   *   to its pre-set `aclUrl`, if not explicitly passed in.
   * @throws {Error} Rejects with an error if it doesn't know where to save, or
   *   with any XHR errors that crop up.
   * @return {Promise<Request>}
   */
  save (aclUrl, rdf, webClient) {
    aclUrl = aclUrl || this.aclUrl
    if (!aclUrl) {
      return Promise.reject(new Error('Cannot save - unknown target url'))
    }
    rdf = rdf || this.rdf
    if (!rdf) {
      return Promise.reject(new Error('Cannot save - no rdf library'))
    }
    webClient = webClient || this.webClient
    if (!webClient) {
      return Promise.reject(new Error('Cannot save - no web client'))
    }
    return webClient.put(aclUrl, this.serialize(rdf))
  }

  /**
   * Serializes this permission set (and all its Authorizations) to a string RDF
   * representation (Turtle by default).
   * Note: invalid authorizations (ones that don't have at least one agent/group,
   * at least one resourceUrl and at least one access mode) do not get serialized,
   * and are instead skipped.
   * @method serialize
   * @param rdf {RDF} RDF Library
   * @param [contentType='text/turtle'] {String}
   * @throws {Error} Rejects with an error if one is encountered during RDF
   *   serialization.
   * @return {Promise<String>} Graph serialized to contentType RDF syntax
   */
  serialize (contentType, rdf) {
    contentType = contentType || 'text/turtle'
    rdf = rdf || this.rdf
    var graph = this.buildGraph(rdf)
    var target = null
    var base = null
    return new Promise(function (resolve, reject) {
      rdf.serialize(target, graph, base, contentType, function (err, result) {
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
 * Returns whether or not a given agent webId is actually a `mailto:` link.
 * Standalone helper function.
 * @param agent {String|Statement} URL string (or RDF `acl:agent` triple)
 * @return {Boolean}
 */
function isMailTo (agent) {
  if (typeof agent === 'string') {
    return agent.startsWith('mailto:')
  } else {
    return agent.object.uri.startsWith('mailto:')
  }
}

PermissionSet.RESOURCE = RESOURCE
PermissionSet.CONTAINER = CONTAINER
module.exports = PermissionSet
