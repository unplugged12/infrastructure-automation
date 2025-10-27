 -- LIST ENDPOINTS
 select * from sys.tcp_endpoints
 go

-- LIST ENDPOINT ENCRYPTION
USE MASTER;
SET NOCOUNT ON;
SELECT
 endpoint_id AS EndpointID
 , [name] AS EndpointName
 , protocol_desc AS ProtocolUsed
 , REPLACE([type_desc], '_', ' ') AS EndpointType
 , role_desc AS RoleType
 , is_encryption_enabled AS IsEncryptionEnabled
 , connection_auth_desc AS ConnectionAuthentication
 , encryption_algorithm_desc AS EncryptionAlgorithm
FROM sys.database_mirroring_endpoints WITH (NOLOCK)
WHERE type = 4 --Database_Mirroring