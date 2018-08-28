'use strict'

const test = require('tape')
const sinon = require('sinon')
const Permission = require('../../src/permission')
const rdf = require('rdflib')
const { parseGraph } = require('./utils')
const { acl } = require('../../src/modes')
const PermissionSet = require('../../src/permission-set')
const aliceWebId = 'https://alice.example.com/#me'

test('PermissionSet checkAccess() test - Append access', t => {
  let resourceUrl = 'https://alice.example.com/docs/file1'
  let aclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(resourceUrl, aclUrl)
  ps.addPermission(aliceWebId, acl.WRITE)
  ps.checkAccess(resourceUrl, aliceWebId, acl.APPEND)
    .then(result => {
      t.ok(result, 'Alice should have Append access implied by Write access')
      t.end()
    })
    .catch(err => {
      t.fail(err)
    })
})

test('PermissionSet checkAccess() test - accessTo', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(containerUrl, containerAclUrl)
  ps.addPermission(aliceWebId, [acl.READ, acl.WRITE])

  ps.checkAccess(containerUrl, aliceWebId, acl.WRITE)
    .then(result => {
      t.ok(result, 'Alice should have write access to container')
      return ps.checkAccess(containerUrl, 'https://someone.else.com/', acl.WRITE)
    })
    .then(result => {
      t.notOk(result, 'Another user should have no write access')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})

test('PermissionSet checkAccess() test - default/inherited', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(containerUrl, containerAclUrl)
  // Now add a default / inherited permission for the container
  let inherit = true
  ps.addPermissionFor(containerUrl, inherit, aliceWebId, acl.READ)

  let resourceUrl = 'https://alice.example.com/docs/file1'
  ps.checkAccess(resourceUrl, aliceWebId, acl.READ)
    .then(result => {
      t.ok(result, 'Alice should have inherited read access to file')
      let randomUser = 'https://someone.else.com/'
      return ps.checkAccess(resourceUrl, randomUser, acl.READ)
    })
    .then(result => {
      t.notOk(result, 'Another user should not have inherited access to file')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})

test('PermissionSet checkAccess() test - public access', function (t) {
  let containerUrl = 'https://alice.example.com/docs/'
  let containerAclUrl = 'https://alice.example.com/docs/.acl'
  let ps = new PermissionSet(containerUrl, containerAclUrl)
  let inherit = true

  // First, let's test an inherited allow public read permission
  let perm1 = new Permission(containerUrl, inherit)
  perm1.setPublic()
  perm1.addMode(acl.READ)
  ps.addSinglePermission(perm1)
  // See if this file has inherited access
  let resourceUrl = 'https://alice.example.com/docs/file1'
  let randomUser = 'https://someone.else.com/'
  ps.checkAccess(resourceUrl, randomUser, acl.READ)
    .then(result => {
      t.ok(result, 'Everyone should have inherited read access to file')
      // Reset the permission set, test a non-default permission
      ps = new PermissionSet()
      let perm2 = new Permission(resourceUrl, !inherit)
      perm2.setPublic()
      perm2.addMode(acl.READ)
      ps.addSinglePermission(perm2)
      return ps.checkAccess(resourceUrl, randomUser, acl.READ)
    })
    .then(result => {
      t.ok(result, 'Everyone should have non-inherited read access to file')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})

test('PermissionSet checkAccess() with remote Group Listings', t => {
  let groupAclSource = require('../resources/acl-with-group-ttl')
  let resourceUrl = 'https://alice.example.com/docs/file2.ttl'
  let aclUrl = 'https://alice.example.com/docs/file2.ttl.acl'

  let groupListingSource = require('../resources/group-listing-ttl')
  let listingUri = 'https://alice.example.com/work-groups'
  let groupUri = listingUri + '#Accounting'
  let fetchGraph = sinon.stub()
    .returns(parseGraph(rdf, listingUri, groupListingSource))
  let options = { fetchGraph }

  let bob = 'https://bob.example.com/profile/card#me'
  let isContainer = false
  let ps = new PermissionSet(resourceUrl, aclUrl, isContainer, { rdf })

  parseGraph(rdf, aclUrl, groupAclSource)
    .then(graph => {
      ps.initFromGraph(graph)
      return ps.checkAccess(resourceUrl, bob, acl.WRITE, options)
    })
    .then(hasAccess => {
      // External group listings have now been loaded/resolved
      t.ok(fetchGraph.calledWith(groupUri, options))
      t.ok(hasAccess, 'Bob should have access as member of group')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail(err)
    })
})
