SELECT r.scope,r.cidr,r.revision,r.recorded,r.active,r.reserved,r.alias,r.tags,r.note
FROM ipam_revision r
WHERE NOT EXISTS (SELECT 1 FROM ipam_revision n WHERE n.scope=r.scope AND n.cidr=r.cidr AND n.revision>r.revision)
ORDER BY r.scope,r.cidr LIMIT 4096;
