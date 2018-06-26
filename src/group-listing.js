const vocab = require('solid-namespace')

/**
 * ACL Group Listing
 * @see https://github.com/solid/web-access-control-spec#groups-of-agents
 * @class GroupListing
 */
class GroupListing {
  /**
   * @constructor
   * @param [options={}] {Object} Options hashmap
   * @param [options.uri] {string|NamedNode} Group URI as appears in ACL file
   *   (e.g. `https://example.com/groups#management`)
   * @param [options.uid] {string} Value of `vcard:hasUID` object
   * @param [options.members={}] {Object} Hashmap of group members, by webId
   * @param [options.listing] {string|NamedNode} Group listing document URI
   * @param [options.rdf] {RDF} RDF library
   * @param [options.graph] {Graph} Parsed graph of the group listing document
   */
  constructor (options = {}) {
    this.uri = options.uri
    this.uid = options.uid
    this.members = options.members || {}
    this.listing = options.listing
    this.rdf = options.rdf
    this.graph = options.graph
    if (this.rdf && this.graph) {
      this.initFromGraph(this.graph, this.rdf)
    }
  }

  /**
   * Factory function, returns a group listing, loaded and initialized
   * with the graph from its uri. Will return null if parsing fails,
   * which can be used to deny access to the resource.
   * @static
   * @param uri {string}
   * @param fetchGraph {Function}
   * @param rdf {RDF}
   * @param options {Object} Options hashmap, passed through to fetchGraph()
   * @return {Promise<GroupListing>}
   */
  static loadFrom (uri, fetchGraph, rdf, options = {}) {
    let group = new GroupListing({ uri, rdf })
    return fetchGraph(uri, options)
      .then(graph => {
        return group.initFromGraph(uri, graph)
      })
      .catch(err => {
        console.error(err)
        return null // Returning null will result in deny, which is suitable in this case 
      })
  }

  /**
   * Adds a member's web id uri to the listing
   * @param webId {string|NamedNode}
   * @return {GroupListing} Chainable
   */
  addMember (webId) {
    if (webId.value) {
      webId = webId.value
    }
    this.members[webId] = true
    return this
  }

  /**
   * Returns the number of members in this listing
   * @return {Number}
   */
  get count () {
    return Object.keys(this.members).length
  }

  /**
   * Tests if a webId uri is present in the members list
   * @param webId {string|NamedNode}
   * @return {Boolean}
   */
  hasMember (webId) {
    if (webId.value) {
      webId = webId.value
    }
    return this.members[webId]
  }

  /**
   * @method initFromGraph
   * @param [uri] {string|NamedNode} Group URI as appears in ACL file
   *   (e.g. `https://example.com/groups#management`)
   * @param [graph] {Graph} Parsed graph
   * @param [rdf] {RDF}
   * @throws {Error}
   * @return {GroupListing} Chainable
   */
  initFromGraph (uri = this.uri, graph = this.graph, rdf = this.rdf) {
    if (!uri) {
      throw new Error('Group URI required to init from graph')
    }
    if (!graph || !rdf) {
      throw new Error('initFromGraph() - graph or rdf library missing')
    }
    let ns = vocab(rdf)
    let group = rdf.namedNode(uri)
    let rdfType = graph.any(group, null, ns.vcard('Group'))
    if (!rdfType) {
      console.warn(`Possibly invalid group '${uri}', missing type vcard:Group`)
    }
    this.uid = graph.anyValue(group, ns.vcard('hasUID'))
    graph.match(group, ns.vcard('hasMember'))
      .forEach(memberMatch => {
        this.addMember(memberMatch.object)
      })
    return this
  }
}

module.exports = GroupListing
