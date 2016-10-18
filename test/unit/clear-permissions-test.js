'use strict'

const test = require('tape')
const SolidResponse = require('solid-web-client/lib/models/response')
const acls = require('../../src/index')  // solid-permissions module
const resourceUrl = 'https://example.com/resource1'
const sinon = require('sinon')
const deleteSpy = sinon.spy()

const mockWebClient = {
  head: (url) => {
    let response = new SolidResponse()
    response.url = url
    response.acl = '.acl'
    return Promise.resolve(response)
  },
  del: deleteSpy
}

test('clearPermissions() test', t => {
  let aclUrl = resourceUrl + '.acl'
  acls.clearPermissions(resourceUrl, mockWebClient)
    .then(() => {
      t.ok(deleteSpy.calledWith, aclUrl,
        'should result in a DELETE call to the .acl url')
      t.end()
    })
    .catch(err => {
      console.log(err)
      t.fail()
    })
})
