/*******************************************************************************
 * Script Name: FailOverBAGs.sql
 * Purpose: Intelligent Availability Group failover script that automatically
 *          detects which BAGs need to be failed over based on the Cust_BAG
 *          primary status. Fails over only secondary BAGs to match Cust_BAG.
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
 *   This script provides intelligent "Bag of Bags" failover functionality.
 *   It uses Cust_BAG as the master/reference AG and fails over all other
 *   secondary BAGs to match. This ensures all AGs remain on the same replica
 *   for consistent application connectivity.
 *
 *   Script logic:
 *     1. Check if Cust_BAG is PRIMARY on current server
 *     2. If not PRIMARY, exit without changes (prevents incorrect failover)
 *     3. If PRIMARY, scan through all other BAGs
 *     4. Fail over any BAGs that are currently SECONDARY
 *     5. Skip BAGs already PRIMARY (already in correct state)
 *
 *   This script is designed to run on Luigi and Mario SQL servers.
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
 *     - Windows Server Failover Clustering configured
 *
 ******************************************************************************
 * DATABASE CONTEXT
 *
 *   Target Database: master (system database)
 *   Creates Objects: No - temporary table #Temp created and dropped
 *   Modifies Data: No - only executes ALTER AVAILABILITY GROUP commands
 *
 *   Affected Availability Groups:
 *     - All AGs except Cust_BAG (which serves as the reference)
 *     - Typically 15+ Availability Groups
 *
 ******************************************************************************
 * PREREQUISITES
 *
 *   Permissions Required:
 *     - sysadmin fixed server role membership
 *     - ALTER AVAILABILITY GROUP permission (included in sysadmin)
 *     - VIEW SERVER STATE permission
 *
 *   Dependencies:
 *     - Cust_BAG must exist and be healthy
 *     - All Availability Groups must be in SYNCHRONIZED state
 *     - WSFC (Windows Server Failover Cluster) must be healthy
 *     - Network connectivity between all replicas
 *
 *   Server Configuration:
 *     - Script must be run on either Luigi or Mario server
 *     - Execute on the server where Cust_BAG is currently PRIMARY
 *     - All replicas must be connected and synchronized
 *
 ******************************************************************************
 * USAGE EXAMPLES
 *
 *   Example 1: Basic execution to fail over secondary BAGs
 *     USE master;
 *     GO
 *     -- Execute script (copy/paste entire script)
 *
 *   Example 2: Pre-flight check before failover
 *     -- Verify all AGs are synchronized
 *     SELECT ag.name, ars.role_desc, ars.synchronization_health_desc
 *     FROM sys.availability_groups ag
 *     JOIN sys.dm_hadr_availability_replica_states ars
 *       ON ag.group_id = ars.group_id
 *     WHERE ars.is_local = 1;
 *     GO
 *     -- Then execute this script
 *
 *   Example 3: Verify results after failover
 *     -- Check all AGs are now PRIMARY
 *     SELECT ag.name, ars.role_desc
 *     FROM sys.availability_groups ag
 *     JOIN sys.dm_hadr_availability_replica_states ars
 *       ON ag.group_id = ars.group_id
 *     WHERE ars.is_local = 1
 *     ORDER BY ag.name;
 *
 ******************************************************************************
 * EXPECTED RESULTS
 *
 *   Output:
 *     - Console messages indicating which BAGs were failed over
 *     - "Cust_BAG not primary. Do not fail over." if run on wrong server
 *     - "Cust_BAG is primary. Make sure the rest are failed over" on success
 *     - Per-BAG messages: "[BAG_name] SECONDARY  Failing over..."
 *     - Per-BAG messages: "[BAG_name] was already primary. It is OK."
 *
 *   Side Effects:
 *     - Application connections terminated during each AG failover
 *     - Brief downtime per AG (5-30 seconds depending on database size)
 *     - All connections must be re-established after failover
 *     - SQL Server Agent jobs on old primary may need manual intervention
 *
 ******************************************************************************
 * PERFORMANCE NOTES
 *
 *   Estimated Execution Time:
 *     - Depends on number of AGs requiring failover
 *     - 5-30 seconds per AG
 *     - Total time: 1-5 minutes for typical environment
 *
 *   Locking Behavior:
 *     - Acquires locks on sys.dm_hadr_name_id_map during scan
 *     - Locks released immediately after temporary table population
 *     - Each ALTER AVAILABILITY GROUP is independent
 *
 *   Optimization Tips:
 *     - Run during maintenance window
 *     - Ensure all AGs are SYNCHRONIZED before running
 *     - Have application teams ready to verify connectivity
 *     - Monitor Windows Cluster quorum during execution
 *
 ******************************************************************************
 * SECURITY CONSIDERATIONS (for Medium/High risk scripts)
 *
 *   Risk Level: CRITICAL
 *
 *   Security Implications:
 *     - Affects production application availability
 *     - Terminates all active database connections per AG
 *     - Can cause cascade failures if cluster unhealthy
 *     - Requires sysadmin privileges (cannot be delegated)
 *
 *   WARNING - PRODUCTION AVAILABILITY:
 *     - Applications will experience brief downtime per AG
 *     - Some applications may require manual restart
 *     - Connection strings must use AG listener names (not server names)
 *     - Estimated total downtime: 1-5 minutes
 *
 *   Best Practices:
 *     - Test in non-production environment first
 *     - Schedule maintenance window with stakeholders
 *     - Verify all AGs are SYNCHRONIZED before executing
 *     - Have rollback plan ready (run script on original primary)
 *     - Monitor WSFC health during execution
 *     - Verify application connectivity after completion
 *
 *   Audit Requirements:
 *     - Document in change management system
 *     - Log execution time and user
 *     - Capture before/after AG states
 *     - Notify application teams of execution window
 *
 ******************************************************************************
 * ROLLBACK PROCEDURE
 *
 *   To fail back to original primary:
 *     1. Connect to original primary server (currently secondary)
 *     2. Verify Cust_BAG is SYNCHRONIZED
 *     3. Run this same script on original primary
 *     4. Script will automatically fail over all AGs back
 *     5. Verify applications reconnect properly
 *
 *   If individual AG fails during failover:
 *     - Check sys.dm_hadr_availability_replica_states for sync status
 *     - Verify network connectivity: ping secondary server
 *     - Check Windows Event Log on both servers
 *     - Manually fail over problematic AG:
 *       ALTER AVAILABILITY GROUP [AG_name] FAILOVER;
 *
 ******************************************************************************
 * NOTES
 *
 *   - Cust_BAG serves as the "master" reference AG
 *   - Script is idempotent - safe to run multiple times
 *   - Only affects AGs that are currently SECONDARY
 *   - Uses temporary table to iterate through AGs
 *   - Dynamic SQL used for AG names (safe - no user input)
 *   - Temporary table automatically dropped at end
 *
 *   Logic Flow:
 *     1. Get Cust_BAG's AG ID from sys.dm_hadr_name_id_map
 *     2. Check if Cust_BAG is PRIMARY on local server
 *     3. If not PRIMARY, print message and exit
 *     4. If PRIMARY, populate #Temp with all other AGs
 *     5. Loop through #Temp and failover each SECONDARY AG
 *     6. Skip AGs already PRIMARY
 *     7. Clean up temporary table
 *
 ******************************************************************************
 * CHANGE LOG
 *
 *   1.0.0 - 2024-10-05 - Initial documentation
 *           - Added comprehensive header
 *           - Documented logic and prerequisites
 *
 ******************************************************************************/

-- Failover Bag of Bags  Runs on Luigi and Mario.  Makes secondary BAGs fail over.

USE master;

-- Get Master BAG id (Cust_BAG is the master.  It has a ) --
DECLARE @Cust_id UNIQUEIDENTIFIER;
DECLARE @id UNIQUEIDENTIFIER;
DECLARE @name VARCHAR(100);
DECLARE @state VARCHAR(20);
SELECT  @cust_id = ag_id 
 FROM sys.dm_hadr_name_id_map 
 WHERE ag_name = 'Cust_BAG';

-- See if Cust_BAG failed over (Is PRIMARY on this machine) --
IF ( SELECT role_desc FROM  sys.dm_hadr_availability_replica_states
     WHERE  group_id = @cust_id AND is_local = 1
   ) <> 'PRIMARY'
    BEGIN
	  PRINT 'Cust_BAG not primary.  Do not fail over.'
      RETURN
    END;

print 'Cust_BAG is primary.  Make sure the rest are failed over'
-- Cust_BAG IS PRIMARY ON THIS MACHINE. FAIL OVER THE REST --

-- Select the name and id of all secondary BAGs --
--   ag_name       ag_id
--   Archive_BAG   4BCFC6FA-5B64-4C1B-93F7-90DCAE8B322B
---  etc...
SELECT ag_name, ag_id
 INTO #Temp
 FROM sys.dm_hadr_name_id_map WHERE ag_name <> 'Cust_BAG';

-- Scan through the list and fail over any that need it --
USE master;
While (Select Count(*) From #Temp) > 0
Begin
  SELECT Top 1 @id = ag_id from #Temp;
  SELECT Top 1 @name = ag_name from #Temp;

  SELECT @state = role_desc
       FROM   sys.dm_hadr_availability_replica_states
       WHERE  group_id = @id AND is_local = 1;

  IF @state <> 'PRIMARY'
    BEGIN
	  print @name + ' ' + @state + '  Failing over...';
      EXEC ('ALTER AVAILABILITY GROUP ' + @name + ' FAILOVER');
    END;
  ELSE
    print @name + ' was already primary.  It is OK.';

  Delete #Temp where ag_id = @id;
END;

drop table #Temp
GO
-- End --