/*******************************************************************************
 * Script Name: ResumeDataMovementOnSecondary.sql
 * Purpose: Resume data synchronization on secondary replica when Availability
 *          Group databases show "Not Synchronized" status. Used after network
 *          interruptions, maintenance, or synchronization pauses.
 *
 * Author: Database Administrator
 * Created: 2024-10-05
 * Modified: 2024-10-05
 * Version: 1.0.0
 * Risk Level: MEDIUM
 *
 ******************************************************************************
 * DESCRIPTION
 *
 *   This script resumes data movement for all Availability Group databases
 *   on the secondary replica server. It's used when databases show "Not
 *   Synchronized" status but the Availability Groups are otherwise healthy.
 *
 *   Common scenarios requiring this script:
 *   - After planned maintenance on secondary server
 *   - Following network interruption between replicas
 *   - After manual SUSPEND of data movement
 *   - When automatic synchronization fails to resume
 *   - After secondary server reboot
 *
 *   The script executes ALTER DATABASE [name] SET HADR RESUME for all 16
 *   databases, allowing them to catch up with the primary replica.
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
 *   Modifies Data: No - only resumes synchronization
 *
 *   Affected Databases (16):
 *     archive, Chariot, Chariot_datawarehouse, Chariottest, ChariotTraining,
 *     Cust, Docs, Eupdate, obr, obrtest, obrTraining, Trantemp,
 *     CompanyBudget, CompanyTransfer, companytransfertest, CompanyTransferTraining
 *
 ******************************************************************************
 * PREREQUISITES
 *
 *   Permissions Required:
 *     - sysadmin fixed server role OR
 *     - ALTER permission on each database
 *     - CONTROL AVAILABILITY GROUP permission
 *
 *   Dependencies:
 *     - Run ONLY on SECONDARY replica server
 *     - Primary replica must be online and accessible
 *     - Network connectivity between replicas must be restored
 *     - Databases must be in SUSPENDED or NOT SYNCHRONIZING state
 *     - Sufficient disk space for log catch-up on secondary
 *     - Sufficient network bandwidth for data catch-up
 *
 *   Verification Before Running:
 *     - Check database synchronization state
 *     - Verify network connectivity to primary
 *     - Confirm sufficient disk space in transaction log drive
 *     - Ensure primary replica is healthy
 *
 ******************************************************************************
 * USAGE EXAMPLES
 *
 *   Example 1: Check which databases need resume
 *     SELECT
 *         ag.name AS AGName,
 *         db.database_name,
 *         drs.synchronization_state_desc,
 *         drs.is_suspended
 *     FROM sys.dm_hadr_database_replica_states drs
 *     JOIN sys.availability_databases_cluster db
 *         ON drs.group_database_id = db.group_database_id
 *     JOIN sys.availability_groups ag
 *         ON drs.group_id = ag.group_id
 *     WHERE drs.is_local = 1
 *         AND (drs.is_suspended = 1
 *             OR drs.synchronization_state_desc <> 'SYNCHRONIZED');
 *
 *   Example 2: Execute resume script
 *     USE master;
 *     GO
 *     -- Execute this script
 *
 *   Example 3: Monitor synchronization progress after resume
 *     SELECT
 *         database_name,
 *         synchronization_state_desc,
 *         log_send_queue_size / 1024.0 AS LogSendQueue_MB,
 *         redo_queue_size / 1024.0 AS RedoQueue_MB
 *     FROM sys.dm_hadr_database_replica_states drs
 *     JOIN sys.availability_databases_cluster db
 *         ON drs.group_database_id = db.group_database_id
 *     WHERE drs.is_local = 1;
 *     GO
 *     -- Re-run every 30 seconds to monitor progress
 *
 ******************************************************************************
 * EXPECTED RESULTS
 *
 *   Output:
 *     - 16 successful "ALTER DATABASE" command completions
 *     - No error messages (if all prerequisites met)
 *     - Databases begin synchronization immediately
 *
 *   Side Effects:
 *     - Network bandwidth usage increase (log shipping catch-up)
 *     - Disk I/O increase on secondary (redo operations)
 *     - Transaction log space usage on secondary
 *     - Synchronization lag until catch-up completes
 *
 ******************************************************************************
 * PERFORMANCE NOTES
 *
 *   Estimated Execution Time:
 *     - Script execution: <1 second (just issues commands)
 *     - Synchronization catch-up: Varies widely
 *       * Minutes if briefly suspended
 *       * Hours if long suspension or large transaction volume
 *
 *   Resource Impact:
 *     - Network bandwidth: Depends on transaction log size to catch up
 *     - Disk I/O: Can be significant if large redo queue
 *     - CPU: Redo worker threads consume CPU during catch-up
 *     - Memory: Buffer pool used for redo operations
 *
 *   Catch-up Duration Factors:
 *     - Size of transaction log queue on primary
 *     - Network bandwidth between replicas
 *     - Disk speed on secondary server
 *     - Concurrent activity on secondary
 *     - Complexity of transactions (indexes, constraints)
 *
 ******************************************************************************
 * SECURITY CONSIDERATIONS
 *
 *   Risk Level: MEDIUM
 *
 *   Security Implications:
 *     - Resumes data flow from primary to secondary
 *     - No data loss risk (secondary catches up to primary)
 *     - Increases resource utilization during catch-up
 *     - May affect secondary replica read-only workloads
 *
 *   Best Practices:
 *     - Run during off-peak hours if possible (reduces performance impact)
 *     - Monitor synchronization progress
 *     - Verify network stability before resuming
 *     - Check disk space before running
 *     - Notify teams if read-only routing may be affected
 *     - Monitor secondary server performance during catch-up
 *
 *   Audit Requirements:
 *     - Document reason for suspension
 *     - Log resume action in change management
 *     - Record synchronization catch-up duration
 *     - Note any performance impact on applications
 *
 ******************************************************************************
 * ROLLBACK PROCEDURE
 *
 *   To suspend data movement again (if needed):
 *     -- Suspend individual database
 *     ALTER DATABASE [database_name] SET HADR SUSPEND;
 *     GO
 *
 *     -- OR suspend all databases (use loop similar to this script)
 *
 *   When to suspend again:
 *     - Secondary server performance degradation
 *     - Network bandwidth saturation
 *     - Need to perform maintenance on secondary
 *     - Disk space issues on secondary
 *
 ******************************************************************************
 * NOTES
 *
 *   - Script must be run on SECONDARY replica only
 *   - Primary replica unaffected by this operation
 *   - Safe to run multiple times (idempotent)
 *   - Already synchronized databases not affected
 *   - Monitor log_send_queue and redo_queue to track progress
 *
 *   Synchronization States:
 *     - SUSPENDED: Data movement manually paused
 *     - NOT SYNCHRONIZING: Synchronization failed or interrupted
 *     - SYNCHRONIZING: Catching up to primary (normal after resume)
 *     - SYNCHRONIZED: Fully caught up (goal state)
 *
 *   Troubleshooting:
 *     - If resume fails: Check network connectivity
 *     - If slow catch-up: Check disk I/O and network bandwidth
 *     - If errors occur: Check SQL Server error log on both replicas
 *     - If stuck: Verify Windows Failover Cluster health
 *
 ******************************************************************************
 * CHANGE LOG
 *
 *   1.0.0 - 2024-10-05 - Initial documentation
 *           - Added comprehensive header
 *           - Documented monitoring queries
 *           - Added troubleshooting guidance
 *
 ******************************************************************************/

-- USE THIS SCRIPT ON THE SECONDARY SERVER TO RESUME DATA MOVEMENT
-- When it says "Not Synchronized"

ALTER DATABASE [archive] SET HADR RESUME
ALTER DATABASE [Chariot] SET HADR RESUME
ALTER DATABASE [Chariot_datawarehouse] SET HADR RESUME
ALTER DATABASE [Chariottest] SET HADR RESUME
ALTER DATABASE [ChariotTraining] SET HADR RESUME
ALTER DATABASE [Cust] SET HADR RESUME
ALTER DATABASE [Docs] SET HADR RESUME
ALTER DATABASE [Eupdate] SET HADR RESUME
ALTER DATABASE [obr] SET HADR RESUME
ALTER DATABASE [obrtest] SET HADR RESUME
ALTER DATABASE [obrTraining] SET HADR RESUME
ALTER DATABASE [Trantemp] SET HADR RESUME
ALTER DATABASE [CompanyBudget] SET HADR RESUME
ALTER DATABASE [CompanyTransfer] SET HADR RESUME
ALTER DATABASE [companytransfertest] SET HADR RESUME
ALTER DATABASE [CompanyTransferTraining] SET HADR RESUME
