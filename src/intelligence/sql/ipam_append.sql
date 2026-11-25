INSERT INTO ipam_revision(scope,cidr,revision,recorded,active,reserved,alias,tags,note)
SELECT ?1,?2,?3+1,?4,?5,?6,?7,?8,?9
WHERE ?3=coalesce((SELECT max(revision) FROM ipam_revision WHERE scope=?1 AND cidr=?2),0)
AND (SELECT count(*) FROM ipam_revision)<16384
AND (?3>0 OR (SELECT count(*) FROM ipam_revision WHERE revision=1)<4096);
