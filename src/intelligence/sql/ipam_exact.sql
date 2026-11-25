SELECT scope,cidr,revision,recorded,active,reserved,alias,tags,note
FROM ipam_revision WHERE scope=?1 AND cidr=?2 AND revision=?3;
