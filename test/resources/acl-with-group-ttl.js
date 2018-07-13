module.exports = `@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#authorization1>
    a acl:Authorization;

    acl:agent
        <https://alice.example.com/#me>;
    acl:agentGroup
        <https://alice.example.com/work-groups#Accounting>;
    acl:accessTo <https://alice.example.com/docs/file2.ttl>;
    acl:mode
        acl:Read, acl:Write, acl:Control;

    acl:origin
        <https://example.com/>.`
