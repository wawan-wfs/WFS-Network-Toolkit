INSERT INTO dhcp6_sample(authority,stamp,payload)
SELECT ?1,?2,?3
WHERE NOT EXISTS(SELECT 1 FROM dhcp6_sample WHERE authority=?1 AND stamp=?2)
AND (SELECT count(*) FROM dhcp6_sample WHERE authority=?1)<120
AND (EXISTS(SELECT 1 FROM dhcp6_sample WHERE authority=?1)
     OR (SELECT count(DISTINCT authority) FROM dhcp6_sample)<32)
AND (SELECT coalesce(sum(length(CAST(payload AS BLOB))),0) FROM dhcp6_sample)
    + length(CAST(?3 AS BLOB)) <= 67108864;
