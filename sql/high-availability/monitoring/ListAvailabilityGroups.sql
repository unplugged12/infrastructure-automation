-- LIST AVAILABILITY GROUPS
SELECT
    ag.name AS 'GroupName' 
   ,cs.replica_server_name AS 'Replica'
   ,rs.role_desc AS 'Role'
   ,REPLACE(ar.availability_mode_desc,'_',' ') AS 'AvailabilityMode'
   ,ar.failover_mode_desc AS 'FailoverMode'
   ,ar.primary_role_allow_connections_desc AS 'ConnectionsInPrimaryRole'
   ,ar.secondary_role_allow_connections_desc AS 'ConnectionsInSecondaryRole'
   ,ar.seeding_mode_desc AS 'SeedingMode'
   ,ar.endpoint_url AS 'EndpointURL'
   ,al.dns_name AS 'Listener'
FROM sys.availability_groups ag
JOIN sys.dm_hadr_availability_group_states ags ON ag.group_id = ags.group_id
JOIN sys.dm_hadr_availability_replica_cluster_states cs ON ags.group_id = cs.group_id 
JOIN sys.availability_replicas ar ON ar.replica_id = cs.replica_id 
JOIN sys.dm_hadr_availability_replica_states rs  ON rs.replica_id = cs.replica_id 
LEFT JOIN sys.availability_group_listeners al ON ar.group_id = al.group_id
