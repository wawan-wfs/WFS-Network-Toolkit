SELECT stamp,payload FROM dhcp6_sample
WHERE authority=?1 ORDER BY stamp DESC LIMIT 20;
