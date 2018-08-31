'use strict'

const test = require('tape')
const rdf = require('rdflib')
const ns = require('solid-namespace')(rdf)
const Permission = require('../../src/permission')
const { acl } = require('../../src/modes')

const resourceUrl = 'https://bob.example.com/docs/file1'
const agentWebId = 'https://bob.example.com/profile/card#me'
// Not really sure what group webIDs will look like, not yet implemented:
const groupWebId = 'https://devteam.example.com/something'

test('a new Permission()', t => {
  let perm = new Permission()
  t.notOk(perm.isAgent())
  t.notOk(perm.isGroup())
  t.notOk(perm.isPublic())
  t.notOk(perm.webId())
  t.notOk(perm.resourceUrl)
  t.equal(perm.accessType, acl.ACCESS_TO)
  t.deepEqual(perm.mailTo, [])
  t.deepEqual(perm.allOrigins(), [])
  t.deepEqual(perm.allModes(), [])
  t.notOk(perm.isInherited(),
    'An Permission should not be inherited (acl:default) by default')
  t.ok(perm.isEmpty(), 'a new Permission should be empty')
  t.end()
})

test('a new Permission for a container', t => {
  let perm = new Permission(resourceUrl, acl.INHERIT)
  t.equal(perm.resourceUrl, resourceUrl)
  t.notOk(perm.webId())
  t.notOk(perm.allowsRead())
  t.notOk(perm.allowsWrite())
  t.notOk(perm.allowsAppend())
  t.notOk(perm.allowsControl())
  t.ok(perm.isInherited(),
    'Permissions for containers should be inherited by default')
  t.equal(perm.accessType, acl.DEFAULT)
  t.end()
})

test('Permission allowsMode() test', t => {
  let perm = new Permission()
  perm.addMode(acl.WRITE)
  t.ok(perm.allowsMode(acl.WRITE), 'perm.allowsMode() should work')
  t.end()
})

test('an Permission allows editing permission modes', t => {
  let perm = new Permission()
  perm.addMode(acl.CONTROL)
  t.notOk(perm.isEmpty(), 'Adding an access mode means no longer empty')
  t.ok(perm.allowsControl(), 'Adding Control mode failed')
  t.notOk(perm.allowsRead(), 'Control mode should not imply Read')
  t.notOk(perm.allowsWrite(), 'Control mode should not imply Write')
  t.notOk(perm.allowsAppend(), 'Control mode should not imply Append')
  // Notice addMode() is chainable:
  perm
    .addMode(acl.READ)
    .addMode(acl.WRITE)
  t.ok(perm.allowsRead(), 'Adding Read mode failed')
  t.ok(perm.allowsWrite(), 'Adding Write mode failed')
  t.equals(perm.allModes().length, 3)
  perm.removeMode(acl.READ)
  t.notOk(perm.allowsRead(), 'Removing Read mode failed')
  perm.removeMode(acl.CONTROL)
  t.notOk(perm.allowsControl(), 'Removing Control mode failed')

  // Note that removing Append mode while retaining Write mode has no effect
  perm.removeMode(acl.APPEND)
  t.ok(perm.allowsWrite(), 'Removing Append should not remove Write mode')
  t.ok(perm.allowsAppend(),
    'Removing Append while retaining Write mode should have no effect')

  perm.removeMode(acl.WRITE)
  t.notOk(perm.allowsWrite(), 'Removing Write mode failed')
  t.end()
})

test('an Permission can add or remove multiple modes', t => {
  let perm = new Permission()
  perm.addMode([acl.READ, acl.WRITE, acl.CONTROL])
  t.ok(perm.allowsRead() && perm.allowsWrite() && perm.allowsControl())
  perm.removeMode([acl.WRITE, acl.READ])
  t.notOk(perm.allowsRead() && perm.allowsWrite())
  t.ok(perm.allowsControl())
  t.end()
})

test('an Permission can only have either an agent or a group', t => {
  let perm1 = new Permission()
  perm1.setAgent(agentWebId)
  t.equal(perm1.agent, agentWebId)
  // Try to set a group while an agent already set
  t.throws(function () {
    perm1.setGroup(groupWebId)
  }, 'Trying to set a group for an perm with an agent should throw an error')
  // Now try the other way -- setting an agent while a group is set
  let perm2 = new Permission()
  perm2.setGroup(groupWebId)
  t.equal(perm2.group, groupWebId)
  t.throws(function () {
    perm2.setAgent(agentWebId)
  }, 'Trying to set an agent for an perm with a group should throw an error')
  t.end()
})

test('acl.WRITE implies acl.APPEND', t => {
  let perm = new Permission()
  perm.addMode(acl.WRITE)
  t.ok(perm.allowsWrite())
  t.ok(perm.allowsAppend(), 'Adding Write mode implies granting Append mode')
  // But not the other way around
  perm = new Permission()
  perm.addMode(acl.APPEND)
  t.ok(perm.allowsAppend(), 'Adding Append mode failed')
  t.notOk(perm.allowsWrite(), 'Adding Append mode should not grant Write mode')

  perm.removeMode(acl.WRITE)
  t.ok(perm.allowsAppend(),
    'Removing Write mode when the perm only had Append mode should do nothing')

  perm.removeMode(acl.APPEND)
  t.notOk(perm.allowsAppend(), 'Removing Append mode failed')
  t.end()
})

test('an Permission can grant Public access', t => {
  let perm = new Permission()
  t.notOk(perm.isPublic(), 'An permission is not public access by default')

  perm.setPublic()
  t.ok(perm.isPublic(), 'setPublic() results in public access')
  t.equal(perm.group, acl.EVERYONE)
  t.notOk(perm.agent)

  perm = new Permission()
  perm.setGroup(acl.EVERYONE)
  t.ok(perm.isPublic(),
    'Adding group access to everyone should result in public access')
  t.ok(perm.group, 'Public access permission is a group permission')
  t.notOk(perm.agent, 'A public access perm should have a null agent')

  perm = new Permission()
  perm.setAgent(acl.EVERYONE)
  t.ok(perm.isPublic(),
    'Setting the agent to everyone should be the same as setPublic()')
  t.end()
})

test('an webId is either the agent or the group id', t => {
  let perm = new Permission()
  perm.setAgent(agentWebId)
  t.equal(perm.webId(), perm.agent)
  perm = new Permission()
  perm.setGroup(groupWebId)
  t.equal(perm.webId(), perm.group)
  t.end()
})

test('hashFragment() on an incomplete permission should fail', t => {
  let perm = new Permission()
  t.throws(function () {
    perm.hashFragment()
  }, 'hashFragment() should fail if both webId AND resourceUrl are missing')
  perm.setAgent(agentWebId)
  t.throws(function () {
    perm.hashFragment()
  }, 'hashFragment() should fail if either webId OR resourceUrl are missing')
  t.end()
})

test('Permission.isValid() test', t => {
  let perm = new Permission()
  t.notOk(perm.isValid(), 'An empty permission should not be valid')
  perm.resourceUrl = resourceUrl
  t.notOk(perm.isValid())
  perm.setAgent(agentWebId)
  t.notOk(perm.isValid())
  perm.addMode(acl.READ)
  t.ok(perm.isValid())
  perm.agent = null
  perm.setGroup(groupWebId)
  t.ok(perm.isValid())
  t.end()
})

test('Permission origins test', t => {
  let perm = new Permission()
  let origin = 'https://example.com/'
  perm.addOrigin(origin)
  t.deepEqual(perm.allOrigins(), [origin])
  t.ok(perm.allowsOrigin(origin))
  perm.removeOrigin(origin)
  t.deepEqual(perm.allOrigins(), [])
  t.notOk(perm.allowsOrigin(origin))
  t.end()
})

test('Comparing newly constructed Permissions', t => {
  let perm1 = new Permission()
  let perm2 = new Permission()
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Comparing Permissions, for a resource', t => {
  let perm1 = new Permission(resourceUrl)
  let perm2 = new Permission()
  t.notOk(perm1.equals(perm2))
  perm2.resourceUrl = resourceUrl
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Comparing Permissions setting Agent', t => {
  let perm1 = new Permission()
  perm1.setAgent(agentWebId)
  let perm2 = new Permission()
  t.notOk(perm1.equals(perm2))
  perm2.setAgent(agentWebId)
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Comparing Permissions with same permissions', t => {
  let perm1 = new Permission()
  perm1.addMode([acl.READ, acl.WRITE])
  let perm2 = new Permission()
  t.notOk(perm1.equals(perm2))
  perm2.addMode([acl.READ, acl.WRITE])
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Comparing Permissions with resource, also permission', t => {
  let perm1 = new Permission(resourceUrl, acl.INHERIT)
  let perm2 = new Permission(resourceUrl)
  t.notOk(perm1.equals(perm2))
  perm2.inherited = acl.INHERIT
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Comparing Permissions with email', t => {
  let perm1 = new Permission()
  perm1.addMailTo('alice@example.com')
  let perm2 = new Permission()
  t.notOk(perm1.equals(perm2))
  perm2.addMailTo('alice@example.com')
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Comparing Permissions with origin', t => {
  let origin = 'https://example.com/'
  let perm1 = new Permission()
  perm1.addOrigin(origin)
  let perm2 = new Permission()
  t.notOk(perm1.equals(perm2))
  perm2.addOrigin(origin)
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Permission.clone() test', t => {
  let perm1 = new Permission(resourceUrl, acl.INHERIT)
  perm1.addMode([acl.READ, acl.WRITE])
  let perm2 = perm1.clone()
  t.ok(perm1.equals(perm2))
  t.end()
})

test('Permission serialize group test', t => {
  let perm = new Permission(resourceUrl)
  perm.addMode(acl.READ)
  let groupUrl = 'https://example.com/work-group'
  perm.setGroup(groupUrl)
  // Serialize the permission
  let triples = perm.rdfStatements(rdf)
  let groupTriple = triples.find((triple) => {
    return triple.predicate.equals(ns.acl('agentGroup'))
  })
  t.ok(groupTriple, 'Serialized perm should have an agentGroup triple')
  t.equals(groupTriple.object.value, groupUrl)
  t.end()
})
