/*==============================================================================
Script Name:    Failover.sql
Purpose:        Manually fail over all SQL Server Availability Groups to the
                secondary replica. Typically used during planned maintenance or
                disaster recovery scenarios.

Author:         Database Administrator
Created:        2024-10-05
Modified:       2024-10-05
Version:        1.0.0

Database:       master (executed from), affects 16 Availability Groups
SQL Version:    SQL Server 2012+ (AlwaysOn Availability Groups required)
Compatibility:  Enterprise Edition or Developer Edition only

Usage:
    -- IMPORTANT: Run on the SECONDARY replica that will become PRIMARY
    -- Verify all replicas are synchronized before executing
    SELECT
 * FROM sys.dm_hadr_availability_replica_states;

    -- Execute failover script
    USE master;
    GO
    -- Copy and execute the ALTER AVAILABILITY GROUP statements

Prerequisites:
    - User must be member of sysadmin fixed server role
    - All Availability Groups must be in SYNCHRONIZED state
    - No active transactions or long-running queries on databases
    - Application downtime window scheduled and communicated
    - All replicas must be connected and healthy
    - Execute on the SECONDARY replica that will become PRIMARY

Returns:
    - No result set
    - Availability Groups will be PRIMARY on current server after execution

Risk Level: CRITICAL

WARNING - PRODUCTION AVAILABILITY GROUP FAILOVER:
    *** THIS OPERATION CAUSES APPLICATION DOWNTIME ***

    - All 16 Availability Groups will failover simultaneously
    - Application connections will be terminated
    - Estimated downtime: 5-30 seconds per AG (depends on database size)
    - Total downtime: Approximately 2-5 minutes for all AGs
    - Applications MUST reconnect after failover
    - Some applications may require manual restart

    BEFORE EXECUTING:
    1. Verify all AGs are SYNCHRONIZED (not SYNCHRONIZING)
    2. Schedule maintenance window with stakeholders
    3. Notify all users of planned downtime
    4. Verify secondary replica has sufficient resources
    5. Ensure application servers can reconnect automatically
    6. Have rollback plan ready (failback script)
    7. Test connectivity from all application servers after

    DURING EXECUTION:
    - Monitor sys.dm_hadr_availability_replica_states for status
    - Watch for error messages
    - Do NOT interrupt the process
    - Each AG failover takes 5-30 seconds

    AFTER EXECUTION:
    - Verify all AGs show as PRIMARY on this server
    - Test application connectivity from each app server
    - Monitor SQL Server error log for issues
    - Check application logs for connection errors
    - Verify data synchronization status

Availability Groups Affected (16 total):
    1.  Archive_bag
    2.  Chariot_bag
    3.  Chariot_Datawarehouse_Bag
    4.  ChariotTest_bag
    5.  ChariotTraining_Bag
    6.  Cust_bag
    7.  Docs_bag
    8.  Eupdate_bag
    9.  OBR_Bag
    10. OBRTest_Bag
    11. OBRTraining_bag
    12. TranTemp_bag
    13. TrojanBudget_bag
    14. TrojanTransfer_Bag
    15. TrojanTransferTest_Bag
    16. TrojanTransferTraining_Bag

Notes:
    - Script must be run on the SECONDARY replica
    - Each ALTER AVAILABILITY GROUP command is synchronous (waits for completion)
    - Failover order: Sequential from top to bottom
    - All databases in AG will failover together
    - Connection strings should use AG listener names (not server names)
    - Applications using multi-subnet failover will reconnect faster
    - Monitor Windows Failover Cluster health during process

Rollback Procedure:
    To fail back to original primary:
    1. Connect to original primary server (now secondary)
    2. Verify all AGs are SYNCHRONIZED
    3. Run this same script on that server
    4. Verify applications reconnect properly

Troubleshooting:
    If failover fails for an AG:
    - Check replica synchronization state
    - Verify network connectivity between replicas
    - Check SQL Server error log on both replicas
    - Ensure Windows Failover Cluster is healthy
    - Verify quorum is healthy: Get-ClusterQuorum (PowerShell)
    - May need to resume data movement: ALTER DATABASE [db] SET HADR RESUME

    Common Error Messages:
    - "Cannot failover AG, replica is not in PRIMARY role"
      Solution: You're on wrong server, run on secondary
    - "Database is not in SYNCHRONIZED state"
      Solution: Wait for synchronization or force failover (data loss risk)
    - "Timeout waiting for AG to failover"
      Solution: Check network, cluster health, try manual failover per AG

Performance Impact:
    - Minimal impact after failover completes
    - During failover: All connections terminated
    - New connections blocked until PRIMARY role established
    - Read-only routing will automatically adjust

Security Considerations:
    - Requires sysadmin role (cannot be delegated)
    - Should be executed only by authorized DBAs
    - Change control approval required for production
    - Document execution in change management system

Example Execution Plan:
    -- 1. Pre-failover verification
    SELECT ag.name AS AGName,
           ar.replica_server_name,
           ars.role_desc,
           ars.synchronization_health_desc,
           ars.connected_state_desc
    FROM sys.availability_groups ag
    JOIN sys.availability_replicas ar ON ag.group_id = ar.group_id
    JOIN sys.dm_hadr_availability_replica_states ars ON ar.replica_id = ars.replica_id
    ORDER BY ag.name, ar.replica_server_name;

    -- 2. Execute failover (run script below)
    -- 3. Post-failover verification (run same query as step 1)

==============================================================================*/

use master
ALTER AVAILABILITY GROUP [Archive_bag] FAILOVER;
ALTER AVAILABILITY GROUP [Chariot_bag] FAILOVER;
ALTER AVAILABILITY GROUP [Chariot_Datawarehouse_Bag] FAILOVER;
ALTER AVAILABILITY GROUP [ChariotTest_bag] FAILOVER;
ALTER AVAILABILITY GROUP [ChariotTraining_Bag] FAILOVER;
ALTER AVAILABILITY GROUP [Cust_bag] FAILOVER;
ALTER AVAILABILITY GROUP [Docs_bag] FAILOVER;
ALTER AVAILABILITY GROUP [Eupdate_bag] FAILOVER;
ALTER AVAILABILITY GROUP [OBR_Bag] FAILOVER;
ALTER AVAILABILITY GROUP [OBRTest_Bag] FAILOVER;
ALTER AVAILABILITY GROUP [OBRTraining_bag] FAILOVER;
ALTER AVAILABILITY GROUP [TranTemp_bag] FAILOVER;
ALTER AVAILABILITY GROUP [TrojanBudget_bag] FAILOVER;
ALTER AVAILABILITY GROUP [TrojanTransfer_Bag] FAILOVER;
ALTER AVAILABILITY GROUP [TrojanTransferTest_Bag] FAILOVER;
ALTER AVAILABILITY GROUP [TrojanTransferTraining_Bag] FAILOVER;
GO
