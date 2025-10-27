/*******************************************************************************
 * Script Name: ResumeDataMovementAndRecoverFailoverOnPrimary.sql
 * Purpose: Emergency recovery script to resume data movement and force
 *          failover with data loss when Availability Groups are in "Not
 *          Synchronizing" state after a failed failover attempt.
 *
 * Author: Database Administrator
 * Created: 2024-10-05
 * Modified: 2024-10-05
 * Version: 1.0.0
 * Risk Level: CRITICAL
 *
 ******************************************************************************
 * DESCRIPTION
 *
 *   This is an EMERGENCY RECOVERY script used when Availability Groups are
 *   stuck in "Not Synchronizing" state and Windows Failover Cluster shows
 *   failed roles. This situation typically occurs after:
 *   - Failed automatic failover
 *   - Network interruption during synchronization
 *   - Unplanned server shutdown or crash
 *   - Database corruption or consistency errors
 *
 *   WARNING: This script uses FORCE_FAILOVER_ALLOW_DATA_LOSS which bypasses
 *   synchronization checks and can result in permanent data loss. Only use
 *   when normal failover has failed and data loss is acceptable.
 *
 *   The script performs for each AG (16 total):
 *     1. Resume data movement: ALTER DATABASE [db] SET HADR RESUME
 *     2. Force failover: ALTER AVAILABILITY GROUP [ag] FORCE_FAILOVER_ALLOW_DATA_LOSS
 *
 ******************************************************************************
 * SQL SERVER COMPATIBILITY
 *
 *   Tested on: SQL Server 2012, 2014, 2016, 2017, 2019
 *   Minimum Version: SQL Server 2012 (11.x) - AlwaysOn AG required
 *   Azure SQL: Not Supported (AlwaysOn AG not available)
 *
 *   Edition Requirements:
 *     - Enterprise Edition or Developer Edition only
 *     - AlwaysOn Availability Groups feature enabled
 *
 ******************************************************************************
 * DATABASE CONTEXT
 *
 *   Target Database: master (executed from)
 *   Creates Objects: No
 *   Modifies Data: Yes - Forces AG failover, potential data loss
 *
 *   Affected Databases (16):
 *     Archive, Chariot, Chariot_datawarehouse, Chariottest, ChariotTraining,
 *     Cust, Docs, Eupdate, obr, obrtest, obrtraining, Trantemp,
 *     TrojanBudget, TrojanTransfer, trojantransfertest, TrojanTransferTraining
 *
 *   Affected Availability Groups (16):
 *     Corresponding *_bag AGs for each database listed above
 *
 ******************************************************************************
 * PREREQUISITES
 *
 *   Permissions Required:
 *     - sysadmin fixed server role membership
 *     - ALTER AVAILABILITY GROUP permission
 *     - ALTER DATABASE permission
 *     - VIEW SERVER STATE permission
 *
 *   Dependencies:
 *     - Run ONLY when Availability Groups show "Not Synchronizing"
 *     - Run ONLY when Windows Failover Cluster roles show as Failed
 *     - Run on the server that should become PRIMARY
 *     - Ensure this is an emergency situation (normal failover has failed)
 *
 *   WARNING Prerequisites:
 *     - BACKUP all databases before running if possible
 *     - Accept that data loss WILL occur
 *     - Have business approval for data loss
 *     - Document the incident for post-mortem analysis
 *
 ******************************************************************************
 * USAGE EXAMPLES
 *
 *   Example 1: Verify AGs are in "Not Synchronizing" state
 *     SELECT ag.name, ars.synchronization_health_desc, ars.role_desc
 *     FROM sys.availability_groups ag
 *     JOIN sys.dm_hadr_availability_replica_states ars
 *       ON ag.group_id = ars.group_id
 *     WHERE ars.is_local = 1;
 *     GO
 *     -- Look for synchronization_health_desc = 'NOT_HEALTHY'
 *
 *   Example 2: Execute recovery script (EXTREME CAUTION)
 *     -- ONLY execute if normal recovery has failed
 *     -- Accept that data loss will occur
 *     USE master;
 *     GO
 *     -- Execute this script
 *
 *   Example 3: Post-execution verification
 *     -- Verify AGs are now PRIMARY and synchronized
 *     SELECT ag.name, ars.role_desc, ars.synchronization_health_desc
 *     FROM sys.availability_groups ag
 *     JOIN sys.dm_hadr_availability_replica_states ars
 *       ON ag.group_id = ars.group_id
 *     WHERE ars.is_local = 1;
 *
 ******************************************************************************
 * EXPECTED RESULTS
 *
 *   Output:
 *     - 32 successful command completions (16 RESUME + 16 FORCE_FAILOVER)
 *     - Each database should transition to PRIMARY role
 *     - Windows Failover Cluster roles should become healthy
 *
 *   Side Effects:
 *     - DATA LOSS: Uncommitted transactions will be lost
 *     - All application connections terminated
 *     - Applications must reconnect after recovery
 *     - Secondary replica may require resynchronization
 *     - Transaction log backups broken (new LSN chain starts)
 *
 ******************************************************************************
 * PERFORMANCE NOTES
 *
 *   Estimated Execution Time:
 *     - 2-5 seconds per AG
 *     - Total time: 1-2 minutes for all 16 AGs
 *
 *   WARNING - DATA LOSS:
 *     - Data loss quantity depends on how long synchronization was broken
 *     - Could be seconds to hours of transactions lost
 *     - No way to recover lost transactions after execution
 *     - Compare transaction logs to determine loss extent
 *
 ******************************************************************************
 * SECURITY CONSIDERATIONS
 *
 *   Risk Level: CRITICAL
 *
 *   Security Implications:
 *     - DATA LOSS GUARANTEED - bypasses synchronization safety checks
 *     - Affects all 16 production databases simultaneously
 *     - Breaks transaction log chain (affects disaster recovery)
 *     - May violate RPO (Recovery Point Objective) SLAs
 *     - Requires sysadmin privileges
 *
 *   WARNING - EMERGENCY USE ONLY:
 *     This script is for DISASTER RECOVERY ONLY when:
 *     - Primary server has failed permanently
 *     - Normal failover commands have failed
 *     - Business approves accepting data loss
 *     - Secondary server must become primary immediately
 *
 *   Best Practices:
 *     - Document business approval before execution
 *     - Take tail-log backup of primary if accessible
 *     - Notify all stakeholders of potential data loss
 *     - Schedule emergency maintenance window
 *     - Have database backups available
 *     - Document data loss extent after recovery
 *
 *   Audit Requirements:
 *     - Log incident in change management system
 *     - Document reason for forced failover
 *     - Record data loss impact assessment
 *     - Create post-mortem report
 *     - Review backup/monitoring procedures
 *
 ******************************************************************************
 * ROLLBACK PROCEDURE
 *
 *   WARNING: Cannot rollback data loss after execution
 *
 *   To restore original primary after recovery:
 *     1. Do NOT attempt to restore original primary immediately
 *     2. Allow new primary to run for business continuity
 *     3. Fix issues on original primary server
 *     4. Resynchronize original primary as secondary:
 *        - Remove database from AG
 *        - Restore full backup from new primary
 *        - Restore transaction log backups
 *        - Re-add database to AG
 *     5. Only failback when fully synchronized and tested
 *
 ******************************************************************************
 * NOTES
 *
 *   - FORCE_FAILOVER_ALLOW_DATA_LOSS bypasses all safety checks
 *   - This is a last resort emergency recovery option
 *   - Normal failover should always be attempted first
 *   - Data loss is guaranteed and cannot be reversed
 *   - Original primary may need complete rebuild
 *   - Secondary replica will need full resynchronization
 *
 *   Post-Recovery Tasks:
 *     - Assess data loss extent (compare transaction logs)
 *     - Notify business users of data loss
 *     - Review and fix root cause of failure
 *     - Update disaster recovery procedures
 *     - Test application functionality thoroughly
 *     - Resynchronize original primary as secondary
 *
 ******************************************************************************
 * CHANGE LOG
 *
 *   1.0.0 - 2024-10-05 - Initial documentation
 *           - Added comprehensive header with warnings
 *           - Documented data loss implications
 *           - Added recovery procedures
 *
 ******************************************************************************/

-- USE THIS AFTER A FAILOVER, AND THE DATABASES SAY "Not Synchronizing"
-- And the roles in the failover cluster manager will be in a failed state
ALTER DATABASE [Archive] SET HADR RESUME
ALTER AVAILABILITY GROUP [Archive_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Chariot] SET HADR RESUME
ALTER AVAILABILITY GROUP [Chariot_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Chariot_datawarehouse] SET HADR RESUME
ALTER AVAILABILITY GROUP [Chariot_datawarehouse_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Chariottest] SET HADR RESUME
ALTER AVAILABILITY GROUP [Chariottest_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [ChariotTraining] SET HADR RESUME
ALTER AVAILABILITY GROUP [ChariotTraining_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Cust] SET HADR RESUME
ALTER AVAILABILITY GROUP [Cust_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Docs] SET HADR RESUME
ALTER AVAILABILITY GROUP [Docs_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Eupdate] SET HADR RESUME
ALTER AVAILABILITY GROUP [Eupdate_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [obr] SET HADR RESUME
ALTER AVAILABILITY GROUP [obr_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [obrtest] SET HADR RESUME
ALTER AVAILABILITY GROUP [obrtest_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [obrtraining] SET HADR RESUME
ALTER AVAILABILITY GROUP [obrtraining_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [Trantemp] SET HADR RESUME
ALTER AVAILABILITY GROUP [Trantemp_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [TrojanBudget] SET HADR RESUME
ALTER AVAILABILITY GROUP [TrojanBudget_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [TrojanTransfer] SET HADR RESUME
ALTER AVAILABILITY GROUP [TrojanTransfer_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [trojantransfertest] SET HADR RESUME
ALTER AVAILABILITY GROUP [trojantransfertest_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS

ALTER DATABASE [TrojanTransferTraining] SET HADR RESUME
ALTER AVAILABILITY GROUP [TrojanTransferTraining_bag] FORCE_FAILOVER_ALLOW_DATA_LOSS
