'use strict'
const rdf = require('rdflib')

function parseGraph (rdf, baseUrl, rdfSource, contentType = 'text/turtle') {
  let graph = rdf.graph()
  return new Promise((resolve, reject) => {
    rdf.parse(rdfSource, graph, baseUrl, contentType, (err, result) => {
      if (err) { return reject(err) }
      if (!result) {
        return reject(new Error('Error serializing the graph to ' +
          contentType))
      }
      resolve(result)
    })
  })
}

module.exports.parseGraph = parseGraph
