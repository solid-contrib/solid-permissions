'use strict'
const test = require('tape')
const sinon = require('sinon')
const rdf = require('rdflib')
const { parseGraph } = require('./utils')
const GroupListing = require('../../src/group-listing')
const groupListingSource = require('../resources/group-listing-ttl')
const listingUri = 'https://example.com/groups'

test('GroupListing empty group test', t => {
  let group = new GroupListing()
  t.equals(group.count, 0, 'A new group should have no members')
  t.notOk(group.uid, 'A new group should have no group UID')
  t.end()
})

test('GroupListing addMember test', t => {
  let group = new GroupListing()
  let bobWebId = 'https://bob.com/#i'
  group.addMember(bobWebId)
  t.equals(group.count, 1)
  t.ok(group.hasMember(bobWebId))
  t.end()
})

test('GroupListing initFromGraph()', t => {
  let group = new GroupListing({ listing: listingUri })
  t.equals(group.listing, listingUri)
  let groupUri = listingUri + '#Accounting'

  parseGraph(rdf, listingUri, groupListingSource)
    .then(graph => {
      group.initFromGraph(groupUri, graph, rdf)
      t.ok(group.uid, 'Group vcard:hasUID should have been parsed')
      t.equals(group.count, 2, 'Two members should have been parsed')
      t.ok(group.hasMember('https://bob.example.com/profile/card#me'))
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})

test('GroupListing.loadFrom test', t => {
  let groupUri = listingUri + '#Accounting'
  let fetchGraph = sinon.stub()
    .returns(parseGraph(rdf, listingUri, groupListingSource))
  let options = {}
  GroupListing.loadFrom(groupUri, fetchGraph, rdf, options)
    .then(group => {
      t.equals(group.count, 2, 'Two members should have been parsed')
      t.ok(fetchGraph.calledWith(groupUri, options))
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})
