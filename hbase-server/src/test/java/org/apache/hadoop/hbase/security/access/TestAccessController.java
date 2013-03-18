/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hbase.security.access;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hbase.Coprocessor;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.HRegionInfo;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.LargeTests;
import org.apache.hadoop.hbase.ServerName;
import org.apache.hadoop.hbase.client.Append;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HTable;
import org.apache.hadoop.hbase.client.Increment;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.RetriesExhaustedWithDetailsException;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessorEnvironment;
import org.apache.hadoop.hbase.io.hfile.CacheConfig;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.mapreduce.LoadIncrementalHFiles;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.protobuf.ProtobufUtil;
import org.apache.hadoop.hbase.protobuf.RequestConverter;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos.AccessControlService;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos.CheckPermissionsRequest;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.RegionCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.RegionServerCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.ScanType;
import org.apache.hadoop.hbase.exceptions.AccessDeniedException;
import org.apache.hadoop.hbase.security.SecureTestUtil;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.Permission.Action;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import com.google.protobuf.BlockingRpcChannel;
import com.google.protobuf.ByteString;
import com.google.protobuf.ServiceException;

/**
 * Performs authorization checks for common operations, according to different
 * levels of authorized users.
 */
@Category(LargeTests.class)
@SuppressWarnings("rawtypes")
public class TestAccessController {
  private static HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  private static Configuration conf;

  // user with all permissions
  private static User SUPERUSER;
  // user granted with all global permission
  private static User USER_ADMIN;
  // user with rw permissions on column family.
  private static User USER_RW;
  // user with read-only permissions
  private static User USER_RO;
  // user is table owner. will have all permissions on table
  private static User USER_OWNER;
  // user with create table permissions alone
  private static User USER_CREATE;
  // user with no permissions
  private static User USER_NONE;

  private static byte[] TEST_TABLE = Bytes.toBytes("testtable");
  private static byte[] TEST_FAMILY = Bytes.toBytes("f1");
  private static byte[] TEST_ROW = Bytes.toBytes("r1");

  private static MasterCoprocessorEnvironment CP_ENV;
  private static AccessController ACCESS_CONTROLLER;
  private static RegionServerCoprocessorEnvironment RSCP_ENV;
  private RegionCoprocessorEnvironment RCP_ENV;

  @BeforeClass
  public static void setupBeforeClass() throws Exception {
    // setup configuration
    conf = TEST_UTIL.getConfiguration();
    conf.set("hbase.master.hfilecleaner.plugins",
      "org.apache.hadoop.hbase.master.cleaner.HFileLinkCleaner," +
      "org.apache.hadoop.hbase.master.snapshot.SnapshotHFileCleaner");
    conf.set("hbase.master.logcleaner.plugins",
      "org.apache.hadoop.hbase.master.snapshot.SnapshotLogCleaner");
    SecureTestUtil.enableSecurity(conf);
    
    // enable TRACE logging for AccessController
    org.apache.log4j.Logger.getLogger("SecurityLogger."+AccessController.class.getName())
      .setLevel(org.apache.log4j.Level.TRACE);

    TEST_UTIL.startMiniCluster();
    MasterCoprocessorHost cpHost = TEST_UTIL.getMiniHBaseCluster().getMaster().getCoprocessorHost();
    cpHost.load(AccessController.class, Coprocessor.PRIORITY_HIGHEST, conf);
    ACCESS_CONTROLLER = (AccessController) cpHost.findCoprocessor(AccessController.class.getName());
    CP_ENV = cpHost.createEnvironment(AccessController.class, ACCESS_CONTROLLER,
      Coprocessor.PRIORITY_HIGHEST, 1, conf);
    RegionServerCoprocessorHost rsHost = TEST_UTIL.getMiniHBaseCluster().getRegionServer(0)
        .getCoprocessorHost();
    RSCP_ENV = rsHost.createEnvironment(AccessController.class, ACCESS_CONTROLLER, 
      Coprocessor.PRIORITY_HIGHEST, 1, conf);

    // Wait for the ACL table to become available
    TEST_UTIL.waitTableEnabled(AccessControlLists.ACL_TABLE_NAME);

    // create a set of test users
    SUPERUSER = User.createUserForTesting(conf, "admin", new String[] { "supergroup" });
    USER_ADMIN = User.createUserForTesting(conf, "admin2", new String[0]);
    USER_RW = User.createUserForTesting(conf, "rwuser", new String[0]);
    USER_RO = User.createUserForTesting(conf, "rouser", new String[0]);
    USER_OWNER = User.createUserForTesting(conf, "owner", new String[0]);
    USER_CREATE = User.createUserForTesting(conf, "tbl_create", new String[0]);
    USER_NONE = User.createUserForTesting(conf, "nouser", new String[0]);
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    TEST_UTIL.shutdownMiniCluster();
  }

  @Before
  public void setUp() throws Exception {
    // Create the test table (owner added to the _acl_ table)
    HBaseAdmin admin = TEST_UTIL.getHBaseAdmin();
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    htd.addFamily(new HColumnDescriptor(TEST_FAMILY));
    htd.setOwner(USER_OWNER);
    admin.createTable(htd);

    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    RegionCoprocessorHost rcpHost = region.getCoprocessorHost();
    RCP_ENV = rcpHost.createEnvironment(AccessController.class, ACCESS_CONTROLLER,
      Coprocessor.PRIORITY_HIGHEST, 1, conf);

    // initilize access control
    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(TEST_TABLE);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);

      protocol.grant(null, RequestConverter.buildGrantRequest(USER_ADMIN.getShortName(),
        null, null, null,
        AccessControlProtos.Permission.Action.ADMIN,
        AccessControlProtos.Permission.Action.CREATE,
        AccessControlProtos.Permission.Action.READ,
        AccessControlProtos.Permission.Action.WRITE));

      protocol.grant(null, RequestConverter.buildGrantRequest(USER_RW.getShortName(),
        TEST_TABLE, TEST_FAMILY, null,
        AccessControlProtos.Permission.Action.READ,
        AccessControlProtos.Permission.Action.WRITE));

      protocol.grant(null, RequestConverter.buildGrantRequest(USER_RO.getShortName(), TEST_TABLE,
        TEST_FAMILY, null, AccessControlProtos.Permission.Action.READ));

      protocol.grant(null, RequestConverter.buildGrantRequest(USER_CREATE.getShortName(),
        TEST_TABLE, null, null, AccessControlProtos.Permission.Action.CREATE));

      assertEquals(4, AccessControlLists.getTablePermissions(conf, TEST_TABLE).size());
    } finally {
      acl.close();
    }
  }

  @After
  public void tearDown() throws Exception {
    // Clean the _acl_ table
    TEST_UTIL.deleteTable(TEST_TABLE);
    assertEquals(0, AccessControlLists.getTablePermissions(conf, TEST_TABLE).size());
  }

  /**
   * An AccessTestAction performs an action that will be examined to confirm
   * the results conform to expected access rights.
   * <p>
   * To indicate an action was allowed, return null or a non empty list of
   * KeyValues.
   * <p>
   * To indicate the action was not allowed, either throw an AccessDeniedException
   * or return an empty list of KeyValues.
   */
  static interface AccessTestAction extends PrivilegedExceptionAction<Object> { }

  public void verifyAllowed(User user, AccessTestAction... actions) throws Exception {
    for (AccessTestAction action : actions) {
      try {
        Object obj = user.runAs(action);
        if (obj != null && obj instanceof List<?>) {
          List<?> results = (List<?>) obj;
          if (results != null && results.isEmpty()) {
            fail("Empty non null results from action for user '" +
                user.getShortName() + "'");
          }
        }
      } catch (AccessDeniedException ade) {
        fail("Expected action to pass for user '" + user.getShortName() + "' but was denied");
      }
    }
  }

  public void verifyAllowed(AccessTestAction action, User... users) throws Exception {
    for (User user : users) {
      verifyAllowed(user, action);
    }
  }

  public void verifyDenied(User user, AccessTestAction... actions) throws Exception {
    for (AccessTestAction action : actions) {
      try {
        Object obj = user.runAs(action);
        if (obj != null && obj instanceof List<?>) {
          List<?> results = (List<?>) obj;
          if (results != null && !results.isEmpty()) {
            fail("Expected no results for user '" + user.getShortName() + "'");
          }
        }
      } catch (IOException e) {
        boolean isAccessDeniedException = false;
        if(e instanceof RetriesExhaustedWithDetailsException) {
          // in case of batch operations, and put, the client assembles a
          // RetriesExhaustedWithDetailsException instead of throwing an
          // AccessDeniedException
          for(Throwable ex : ((RetriesExhaustedWithDetailsException) e).getCauses()) {
            if (ex instanceof AccessDeniedException) {
              isAccessDeniedException = true;
              break;
            }
          }
        }
        else {
          // For doBulkLoad calls AccessDeniedException
          // is buried in the stack trace
          Throwable ex = e;
          do {
            if (ex instanceof AccessDeniedException) {
              isAccessDeniedException = true;
              break;
            }
          } while((ex = ex.getCause()) != null);
        }
        if (!isAccessDeniedException) {
          fail("Not receiving AccessDeniedException for user '" + user.getShortName() + "'");
        }
      } catch (UndeclaredThrowableException ute) {
        // TODO why we get a PrivilegedActionException, which is unexpected?
        Throwable ex = ute.getUndeclaredThrowable();
        if (ex instanceof PrivilegedActionException) {
          ex = ((PrivilegedActionException) ex).getException();
        }
        if (ex instanceof ServiceException) {
          ServiceException se = (ServiceException)ex;
          if (se.getCause() != null && se.getCause() instanceof AccessDeniedException) {
            // expected result
            return;
          }
        }
        fail("Not receiving AccessDeniedException for user '" + user.getShortName() + "'");
      }
    }
  }

  public void verifyDenied(AccessTestAction action, User... users) throws Exception {
    for (User user : users) {
      verifyDenied(user, action);
    }
  }

  @Test
  public void testTableCreate() throws Exception {
    AccessTestAction createTable = new AccessTestAction() {
      public Object run() throws Exception {
        HTableDescriptor htd = new HTableDescriptor("testnewtable");
        htd.addFamily(new HColumnDescriptor(TEST_FAMILY));
        ACCESS_CONTROLLER.preCreateTable(ObserverContext.createAndPrepare(CP_ENV, null), htd, null);
        return null;
      }
    };

    // verify that superuser can create tables
    verifyAllowed(createTable, SUPERUSER, USER_ADMIN);

    // all others should be denied
    verifyDenied(createTable, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testTableModify() throws Exception {
    AccessTestAction modifyTable = new AccessTestAction() {
      public Object run() throws Exception {
        HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
        htd.addFamily(new HColumnDescriptor(TEST_FAMILY));
        htd.addFamily(new HColumnDescriptor("fam_" + User.getCurrent().getShortName()));
        ACCESS_CONTROLLER.preModifyTable(ObserverContext.createAndPrepare(CP_ENV, null),
          TEST_TABLE, htd);
        return null;
      }
    };

    verifyAllowed(modifyTable, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(modifyTable, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testTableDelete() throws Exception {
    AccessTestAction deleteTable = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER
            .preDeleteTable(ObserverContext.createAndPrepare(CP_ENV, null), TEST_TABLE);
        return null;
      }
    };

    verifyAllowed(deleteTable, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(deleteTable, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testAddColumn() throws Exception {
    final HColumnDescriptor hcd = new HColumnDescriptor("fam_new");
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preAddColumn(ObserverContext.createAndPrepare(CP_ENV, null), TEST_TABLE,
          hcd);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(action, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testModifyColumn() throws Exception {
    final HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(10);
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preModifyColumn(ObserverContext.createAndPrepare(CP_ENV, null),
          TEST_TABLE, hcd);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(action, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testDeleteColumn() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preDeleteColumn(ObserverContext.createAndPrepare(CP_ENV, null),
          TEST_TABLE, TEST_FAMILY);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(action, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testTableDisable() throws Exception {
    AccessTestAction disableTable = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preDisableTable(ObserverContext.createAndPrepare(CP_ENV, null),
          TEST_TABLE);
        return null;
      }
    };

    AccessTestAction disableAclTable = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preDisableTable(ObserverContext.createAndPrepare(CP_ENV, null),
            AccessControlLists.ACL_TABLE_NAME);
        return null;
      }
    };

    verifyAllowed(disableTable, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(disableTable, USER_RW, USER_RO, USER_NONE);
    
    // No user should be allowed to disable _acl_ table
    verifyDenied(disableAclTable, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER, USER_RW, USER_RO);
  }

  @Test
  public void testTableEnable() throws Exception {
    AccessTestAction enableTable = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER
            .preEnableTable(ObserverContext.createAndPrepare(CP_ENV, null), TEST_TABLE);
        return null;
      }
    };

    verifyAllowed(enableTable, SUPERUSER, USER_ADMIN, USER_CREATE, USER_OWNER);
    verifyDenied(enableTable, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testMove() throws Exception {
    Map<HRegionInfo, ServerName> regions;
    HTable table = new HTable(TEST_UTIL.getConfiguration(), TEST_TABLE);
    try {
      regions = table.getRegionLocations();
    } finally {
      table.close();
    }
    final Map.Entry<HRegionInfo, ServerName> firstRegion = regions.entrySet().iterator().next();
    final ServerName server = TEST_UTIL.getHBaseCluster().getRegionServer(0).getServerName();
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preMove(ObserverContext.createAndPrepare(CP_ENV, null),
          firstRegion.getKey(), server, server);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testAssign() throws Exception {
    Map<HRegionInfo, ServerName> regions;
    HTable table = new HTable(TEST_UTIL.getConfiguration(), TEST_TABLE);
    try {
      regions = table.getRegionLocations();
    } finally {
      table.close();
    }
    final Map.Entry<HRegionInfo, ServerName> firstRegion = regions.entrySet().iterator().next();

    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preAssign(ObserverContext.createAndPrepare(CP_ENV, null),
          firstRegion.getKey());
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testUnassign() throws Exception {
    Map<HRegionInfo, ServerName> regions;
    HTable table = new HTable(TEST_UTIL.getConfiguration(), TEST_TABLE);
    try {
      regions = table.getRegionLocations();
    } finally {
      table.close();
    }
    final Map.Entry<HRegionInfo, ServerName> firstRegion = regions.entrySet().iterator().next();

    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preUnassign(ObserverContext.createAndPrepare(CP_ENV, null),
          firstRegion.getKey(), false);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testBalance() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preBalance(ObserverContext.createAndPrepare(CP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_OWNER, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testBalanceSwitch() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preBalanceSwitch(ObserverContext.createAndPrepare(CP_ENV, null), true);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_OWNER, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testShutdown() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preShutdown(ObserverContext.createAndPrepare(CP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_OWNER, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testStopMaster() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preStopMaster(ObserverContext.createAndPrepare(CP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_OWNER, USER_RW, USER_RO, USER_NONE);
  }

  private void verifyWrite(AccessTestAction action) throws Exception {
    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER, USER_RW);
    verifyDenied(action, USER_NONE, USER_CREATE, USER_RO);
  }

  @Test
  public void testSplit() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preSplit(ObserverContext.createAndPrepare(RCP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testSplitWithSplitRow() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preSplit(
            ObserverContext.createAndPrepare(RCP_ENV, null),
            Bytes.toBytes("row2"));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testFlush() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preFlush(ObserverContext.createAndPrepare(RCP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testCompact() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preCompact(ObserverContext.createAndPrepare(RCP_ENV, null), null, null,
          ScanType.COMPACT_RETAIN_DELETES);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testPreCompactSelection() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preCompactSelection(ObserverContext.createAndPrepare(RCP_ENV, null), null, null);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  private void verifyRead(AccessTestAction action) throws Exception {
    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER, USER_RW, USER_RO);
    verifyDenied(action, USER_NONE, USER_CREATE);
  }

  private void verifyReadWrite(AccessTestAction action) throws Exception {
    verifyAllowed(action, SUPERUSER, USER_ADMIN, USER_OWNER, USER_RW);
    verifyDenied(action, USER_NONE, USER_CREATE, USER_RO);
  }

  @Test
  public void testRead() throws Exception {
    // Store some data
    AccessTestAction putAction = new AccessTestAction() {
      public Object run() throws Exception {
        Put put = new Put(TEST_ROW);
        put.add(TEST_FAMILY, Bytes.toBytes("q"), Bytes.toBytes("value"));
        HTable t = new HTable(conf, TEST_TABLE);
        t.put(put);
        return null;
      }
    };
    verifyAllowed(putAction, USER_OWNER);

    // get action
    AccessTestAction getAction = new AccessTestAction() {
      public Object run() throws Exception {
        Get g = new Get(TEST_ROW);
        g.addFamily(TEST_FAMILY);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          return t.get(g).list();
        } finally {
          t.close();
        }
      }
    };
    verifyRead(getAction);

    // action for scanning
    AccessTestAction scanAction = new AccessTestAction() {
      public Object run() throws Exception {
        List<KeyValue> result = new ArrayList<KeyValue>();
        Scan s = new Scan();
        s.addFamily(TEST_FAMILY);

        HTable table = new HTable(conf, TEST_TABLE);
        try {
          ResultScanner scanner = table.getScanner(s);
          try {
            for (Result r = scanner.next(); r != null; r = scanner.next()) {
              result.addAll(r.list());
            }
          } catch (IOException e) {
          } finally {
            scanner.close();
          }
        } finally {
          table.close();
        }
        return result;
      }
    };
    verifyRead(scanAction);
  }

  @Test
  // test put, delete, increment
  public void testWrite() throws Exception {
    // put action
    AccessTestAction putAction = new AccessTestAction() {
      public Object run() throws Exception {
        Put p = new Put(Bytes.toBytes("random_row"));
        p.add(TEST_FAMILY, Bytes.toBytes("Qualifier"), Bytes.toBytes(1));
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.put(p);
        } finally {
          t.close();
        }
        return null;
      }
    };
    verifyWrite(putAction);

    // delete action
    AccessTestAction deleteAction = new AccessTestAction() {
      public Object run() throws Exception {
        Delete d = new Delete(Bytes.toBytes("random_row"));
        d.deleteFamily(TEST_FAMILY);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.delete(d);
        } finally {
          t.close();
        }
        return null;
      }
    };
    verifyWrite(deleteAction);

    // increment action
    AccessTestAction incrementAction = new AccessTestAction() {
      public Object run() throws Exception {
        Increment inc = new Increment(Bytes.toBytes("random_row"));
        inc.addColumn(TEST_FAMILY, Bytes.toBytes("Qualifier"), 1);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.increment(inc);
        } finally {
          t.close();
        }
        return null;
      }
    };
    verifyWrite(incrementAction);
  }

  @Test
  public void testReadWrite() throws Exception {
    // action for checkAndDelete
    AccessTestAction checkAndDeleteAction = new AccessTestAction() {
      public Object run() throws Exception {
        Delete d = new Delete(Bytes.toBytes("random_row"));
        d.deleteFamily(TEST_FAMILY);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.checkAndDelete(Bytes.toBytes("random_row"), TEST_FAMILY, Bytes.toBytes("q"),
            Bytes.toBytes("test_value"), d);
        } finally {
          t.close();
        }
        return null;
      }
    };
    verifyReadWrite(checkAndDeleteAction);

    AccessTestAction checkAndPut = new AccessTestAction() {
      public Object run() throws Exception {
        Put p = new Put(Bytes.toBytes("random_row"));
        p.add(TEST_FAMILY, Bytes.toBytes("Qualifier"), Bytes.toBytes(1));
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.checkAndPut(Bytes.toBytes("random_row"), TEST_FAMILY, Bytes.toBytes("q"),
           Bytes.toBytes("test_value"), p);
        } finally {
          t.close();
        }
        return null;
      }
    };
    verifyReadWrite(checkAndPut);
  }

  @Test
  public void testBulkLoad() throws Exception {
    FileSystem fs = TEST_UTIL.getTestFileSystem();
    final Path dir = TEST_UTIL.getDataTestDir("testBulkLoad");
    fs.mkdirs(dir);
    //need to make it globally writable
    //so users creating HFiles have write permissions
    fs.setPermission(dir, FsPermission.valueOf("-rwxrwxrwx"));

    AccessTestAction bulkLoadAction = new AccessTestAction() {
      public Object run() throws Exception {
        int numRows = 3;

        //Making the assumption that the test table won't split between the range
        byte[][][] hfileRanges = {{{(byte)0}, {(byte)9}}};

        Path bulkLoadBasePath = new Path(dir, new Path(User.getCurrent().getName()));
        new BulkLoadHelper(bulkLoadBasePath)
            .bulkLoadHFile(TEST_TABLE, TEST_FAMILY, Bytes.toBytes("q"), hfileRanges, numRows);

        return null;
      }
    };
    verifyWrite(bulkLoadAction);

    // Reinit after the bulk upload
    TEST_UTIL.getHBaseAdmin().disableTable(TEST_TABLE);
    TEST_UTIL.getHBaseAdmin().enableTable(TEST_TABLE);
  }

  public class BulkLoadHelper {
    private final FileSystem fs;
    private final Path loadPath;
    private final Configuration conf;

    public BulkLoadHelper(Path loadPath) throws IOException {
      fs = TEST_UTIL.getTestFileSystem();
      conf = TEST_UTIL.getConfiguration();
      loadPath = loadPath.makeQualified(fs);
      this.loadPath = loadPath;
    }

    private void createHFile(Path path,
        byte[] family, byte[] qualifier,
        byte[] startKey, byte[] endKey, int numRows) throws IOException {

      HFile.Writer writer = null;
      long now = System.currentTimeMillis();
      try {
        writer = HFile.getWriterFactory(conf, new CacheConfig(conf))
            .withPath(fs, path)
            .withComparator(KeyValue.KEY_COMPARATOR)
            .create();
        // subtract 2 since numRows doesn't include boundary keys
        for (byte[] key : Bytes.iterateOnSplits(startKey, endKey, true, numRows-2)) {
          KeyValue kv = new KeyValue(key, family, qualifier, now, key);
          writer.append(kv);
        }
      } finally {
        if(writer != null)
          writer.close();
      }
    }

    private void bulkLoadHFile(
        byte[] tableName,
        byte[] family,
        byte[] qualifier,
        byte[][][] hfileRanges,
        int numRowsPerRange) throws Exception {

      Path familyDir = new Path(loadPath, Bytes.toString(family));
      fs.mkdirs(familyDir);
      int hfileIdx = 0;
      for (byte[][] range : hfileRanges) {
        byte[] from = range[0];
        byte[] to = range[1];
        createHFile(new Path(familyDir, "hfile_"+(hfileIdx++)),
            family, qualifier, from, to, numRowsPerRange);
      }
      //set global read so RegionServer can move it
      setPermission(loadPath, FsPermission.valueOf("-rwxrwxrwx"));

      HTable table = new HTable(conf, tableName);
      try {
        TEST_UTIL.waitTableEnabled(tableName);
        LoadIncrementalHFiles loader = new LoadIncrementalHFiles(conf);
        loader.doBulkLoad(loadPath, table);
      } finally {
        table.close();
      }
    }

    public void setPermission(Path dir, FsPermission perm) throws IOException {
      if(!fs.getFileStatus(dir).isDir()) {
        fs.setPermission(dir,perm);
      }
      else {
        for(FileStatus el : fs.listStatus(dir)) {
          fs.setPermission(el.getPath(), perm);
          setPermission(el.getPath() , perm);
        }
      }
    }
  }

  @Test
  public void testAppend() throws Exception {

    AccessTestAction appendAction = new AccessTestAction() {
      public Object run() throws Exception {
        byte[] row = Bytes.toBytes("random_row");
        byte[] qualifier = Bytes.toBytes("q");
        Put put = new Put(row);
        put.add(TEST_FAMILY, qualifier, Bytes.toBytes(1));
        Append append = new Append(row);
        append.add(TEST_FAMILY, qualifier, Bytes.toBytes(2));
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.put(put);
          t.append(append);
        } finally {
          t.close();
        }
        return null;
      }
    };

    verifyAllowed(appendAction, SUPERUSER, USER_ADMIN, USER_OWNER, USER_RW);
    verifyDenied(appendAction, USER_CREATE, USER_RO, USER_NONE);
  }

  @Test
  public void testPostGrantRevoke() throws Exception {
    final byte[] tableName = Bytes.toBytes("TempTable");
    final byte[] family1 = Bytes.toBytes("f1");
    final byte[] family2 = Bytes.toBytes("f2");
    final byte[] qualifier = Bytes.toBytes("q");

    // create table
    HBaseAdmin admin = TEST_UTIL.getHBaseAdmin();
    if (admin.tableExists(tableName)) {
      admin.disableTable(tableName);
      admin.deleteTable(tableName);
    }
    HTableDescriptor htd = new HTableDescriptor(tableName);
    htd.addFamily(new HColumnDescriptor(family1));
    htd.addFamily(new HColumnDescriptor(family2));
    admin.createTable(htd);

    // create temp users
    User tblUser = User
        .createUserForTesting(TEST_UTIL.getConfiguration(), "tbluser", new String[0]);
    User gblUser = User
        .createUserForTesting(TEST_UTIL.getConfiguration(), "gbluser", new String[0]);

    // prepare actions:
    AccessTestAction putActionAll = new AccessTestAction() {
      public Object run() throws Exception {
        Put p = new Put(Bytes.toBytes("a"));
        p.add(family1, qualifier, Bytes.toBytes("v1"));
        p.add(family2, qualifier, Bytes.toBytes("v2"));
        HTable t = new HTable(conf, tableName);
        try {
          t.put(p);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction putAction1 = new AccessTestAction() {
      public Object run() throws Exception {
        Put p = new Put(Bytes.toBytes("a"));
        p.add(family1, qualifier, Bytes.toBytes("v1"));
        HTable t = new HTable(conf, tableName);
        try {
          t.put(p);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction putAction2 = new AccessTestAction() {
      public Object run() throws Exception {
        Put p = new Put(Bytes.toBytes("a"));
        p.add(family2, qualifier, Bytes.toBytes("v2"));
        HTable t = new HTable(conf, tableName);
        try {
          t.put(p);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction getActionAll = new AccessTestAction() {
      public Object run() throws Exception {
        Get g = new Get(Bytes.toBytes("random_row"));
        g.addFamily(family1);
        g.addFamily(family2);
        HTable t = new HTable(conf, tableName);
        try {
          t.get(g);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction getAction1 = new AccessTestAction() {
      public Object run() throws Exception {
        Get g = new Get(Bytes.toBytes("random_row"));
        g.addFamily(family1);
        HTable t = new HTable(conf, tableName);
        try {
          t.get(g);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction getAction2 = new AccessTestAction() {
      public Object run() throws Exception {
        Get g = new Get(Bytes.toBytes("random_row"));
        g.addFamily(family2);
        HTable t = new HTable(conf, tableName);
        try {
          t.get(g);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction deleteActionAll = new AccessTestAction() {
      public Object run() throws Exception {
        Delete d = new Delete(Bytes.toBytes("random_row"));
        d.deleteFamily(family1);
        d.deleteFamily(family2);
        HTable t = new HTable(conf, tableName);
        try {
          t.delete(d);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction deleteAction1 = new AccessTestAction() {
      public Object run() throws Exception {
        Delete d = new Delete(Bytes.toBytes("random_row"));
        d.deleteFamily(family1);
        HTable t = new HTable(conf, tableName);
        try {
          t.delete(d);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction deleteAction2 = new AccessTestAction() {
      public Object run() throws Exception {
        Delete d = new Delete(Bytes.toBytes("random_row"));
        d.deleteFamily(family2);
        HTable t = new HTable(conf, tableName);
        try {
          t.delete(d);
        } finally {
          t.close();
        }
        return null;
      }
    };

    // initial check:
    verifyDenied(tblUser, getActionAll, getAction1, getAction2);
    verifyDenied(tblUser, putActionAll, putAction1, putAction2);
    verifyDenied(tblUser, deleteActionAll, deleteAction1, deleteAction2);

    verifyDenied(gblUser, getActionAll, getAction1, getAction2);
    verifyDenied(gblUser, putActionAll, putAction1, putAction2);
    verifyDenied(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // grant table read permission
    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, tblUser.getShortName(),
        tableName, null, null, Permission.Action.READ);
      ProtobufUtil.grant(protocol, gblUser.getShortName(),
        null, null, null, Permission.Action.READ);
    } finally {
      acl.close();
    }

    Thread.sleep(100);
    // check
    verifyAllowed(tblUser, getActionAll, getAction1, getAction2);
    verifyDenied(tblUser, putActionAll, putAction1, putAction2);
    verifyDenied(tblUser, deleteActionAll, deleteAction1, deleteAction2);

    verifyAllowed(gblUser, getActionAll, getAction1, getAction2);
    verifyDenied(gblUser, putActionAll, putAction1, putAction2);
    verifyDenied(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // grant table write permission
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, tblUser.getShortName(),
        tableName, null, null, Permission.Action.WRITE);
      ProtobufUtil.grant(protocol, gblUser.getShortName(),
        null, null, null, Permission.Action.WRITE);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyDenied(tblUser, getActionAll, getAction1, getAction2);
    verifyAllowed(tblUser, putActionAll, putAction1, putAction2);
    verifyAllowed(tblUser, deleteActionAll, deleteAction1, deleteAction2);

    verifyDenied(gblUser, getActionAll, getAction1, getAction2);
    verifyAllowed(gblUser, putActionAll, putAction1, putAction2);
    verifyAllowed(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // revoke table permission
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, tblUser.getShortName(), tableName, null, null,
        Permission.Action.READ, Permission.Action.WRITE);
      ProtobufUtil.revoke(protocol, tblUser.getShortName(), tableName, null, null);
      ProtobufUtil.revoke(protocol, gblUser.getShortName(), null, null, null);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyDenied(tblUser, getActionAll, getAction1, getAction2);
    verifyDenied(tblUser, putActionAll, putAction1, putAction2);
    verifyDenied(tblUser, deleteActionAll, deleteAction1, deleteAction2);

    verifyDenied(gblUser, getActionAll, getAction1, getAction2);
    verifyDenied(gblUser, putActionAll, putAction1, putAction2);
    verifyDenied(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // grant column family read permission
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, tblUser.getShortName(),
        tableName, family1, null, Permission.Action.READ);
      ProtobufUtil.grant(protocol, gblUser.getShortName(),
        null, null, null, Permission.Action.READ);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    // Access should be denied for family2
    verifyAllowed(tblUser, getActionAll, getAction1);
    verifyDenied(tblUser, getAction2);
    verifyDenied(tblUser, putActionAll, putAction1, putAction2);
    verifyDenied(tblUser, deleteActionAll, deleteAction1, deleteAction2);

    verifyAllowed(gblUser, getActionAll, getAction1, getAction2);
    verifyDenied(gblUser, putActionAll, putAction1, putAction2);
    verifyDenied(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // grant column family write permission
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, tblUser.getShortName(),
        tableName, family2, null, Permission.Action.WRITE);
      ProtobufUtil.grant(protocol, gblUser.getShortName(),
        null, null, null, Permission.Action.WRITE);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    // READ from family1, WRITE to family2 are allowed
    verifyAllowed(tblUser, getActionAll, getAction1);
    verifyAllowed(tblUser, putAction2, deleteAction2);
    verifyDenied(tblUser, getAction2);
    verifyDenied(tblUser, putActionAll, putAction1);
    verifyDenied(tblUser, deleteActionAll, deleteAction1);

    verifyDenied(gblUser, getActionAll, getAction1, getAction2);
    verifyAllowed(gblUser, putActionAll, putAction1, putAction2);
    verifyAllowed(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // revoke column family permission
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.revoke(protocol, tblUser.getShortName(), tableName, family2, null);
      ProtobufUtil.revoke(protocol, gblUser.getShortName(), null, null, null);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    // Revoke on family2 should not have impact on family1 permissions
    verifyAllowed(tblUser, getActionAll, getAction1);
    verifyDenied(tblUser, getAction2);
    verifyDenied(tblUser, putActionAll, putAction1, putAction2);
    verifyDenied(tblUser, deleteActionAll, deleteAction1, deleteAction2);

    // Should not have access as global permissions are completely revoked
    verifyDenied(gblUser, getActionAll, getAction1, getAction2);
    verifyDenied(gblUser, putActionAll, putAction1, putAction2);
    verifyDenied(gblUser, deleteActionAll, deleteAction1, deleteAction2);

    // delete table
    admin.disableTable(tableName);
    admin.deleteTable(tableName);
  }

  private boolean hasFoundUserPermission(UserPermission userPermission, List<UserPermission> perms) {
    return perms.contains(userPermission);
  }

  @Test
  public void testPostGrantRevokeAtQualifierLevel() throws Exception {
    final byte[] tableName = Bytes.toBytes("testGrantRevokeAtQualifierLevel");
    final byte[] family1 = Bytes.toBytes("f1");
    final byte[] family2 = Bytes.toBytes("f2");
    final byte[] qualifier = Bytes.toBytes("q");

    // create table
    HBaseAdmin admin = TEST_UTIL.getHBaseAdmin();
    if (admin.tableExists(tableName)) {
      admin.disableTable(tableName);
      admin.deleteTable(tableName);
    }
    HTableDescriptor htd = new HTableDescriptor(tableName);
    htd.addFamily(new HColumnDescriptor(family1));
    htd.addFamily(new HColumnDescriptor(family2));
    admin.createTable(htd);

    // create temp users
    User user = User.createUserForTesting(TEST_UTIL.getConfiguration(), "user", new String[0]);

    AccessTestAction getQualifierAction = new AccessTestAction() {
      public Object run() throws Exception {
        Get g = new Get(Bytes.toBytes("random_row"));
        g.addColumn(family1, qualifier);
        HTable t = new HTable(conf, tableName);
        try {
          t.get(g);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction putQualifierAction = new AccessTestAction() {
      public Object run() throws Exception {
        Put p = new Put(Bytes.toBytes("random_row"));
        p.add(family1, qualifier, Bytes.toBytes("v1"));
        HTable t = new HTable(conf, tableName);
        try {
          t.put(p);
        } finally {
          t.close();
        }
        return null;
      }
    };
    AccessTestAction deleteQualifierAction = new AccessTestAction() {
      public Object run() throws Exception {
        Delete d = new Delete(Bytes.toBytes("random_row"));
        d.deleteColumn(family1, qualifier);
        // d.deleteFamily(family1);
        HTable t = new HTable(conf, tableName);
        try {
          t.delete(d);
        } finally {
          t.close();
        }
        return null;
      }
    };

    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.revoke(protocol, user.getShortName(), tableName, family1, null);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyDenied(user, getQualifierAction);
    verifyDenied(user, putQualifierAction);
    verifyDenied(user, deleteQualifierAction);

    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, user.getShortName(),
        tableName, family1, qualifier, Permission.Action.READ);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyAllowed(user, getQualifierAction);
    verifyDenied(user, putQualifierAction);
    verifyDenied(user, deleteQualifierAction);

    // only grant write permission
    // TODO: comment this portion after HBASE-3583
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, user.getShortName(),
        tableName, family1, qualifier, Permission.Action.WRITE);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyDenied(user, getQualifierAction);
    verifyAllowed(user, putQualifierAction);
    verifyAllowed(user, deleteQualifierAction);

    // grant both read and write permission.
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, user.getShortName(),
        tableName, family1, qualifier,
          Permission.Action.READ, Permission.Action.WRITE);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyAllowed(user, getQualifierAction);
    verifyAllowed(user, putQualifierAction);
    verifyAllowed(user, deleteQualifierAction);

    // revoke family level permission won't impact column level.
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.revoke(protocol, user.getShortName(),
        tableName, family1, qualifier);
    } finally {
      acl.close();
    }

    Thread.sleep(100);

    verifyDenied(user, getQualifierAction);
    verifyDenied(user, putQualifierAction);
    verifyDenied(user, deleteQualifierAction);

    // delete table
    admin.disableTable(tableName);
    admin.deleteTable(tableName);
  }

  @Test
  public void testPermissionList() throws Exception {
    final byte[] tableName = Bytes.toBytes("testPermissionList");
    final byte[] family1 = Bytes.toBytes("f1");
    final byte[] family2 = Bytes.toBytes("f2");
    final byte[] qualifier = Bytes.toBytes("q");

    // create table
    HBaseAdmin admin = TEST_UTIL.getHBaseAdmin();
    if (admin.tableExists(tableName)) {
      admin.disableTable(tableName);
      admin.deleteTable(tableName);
    }
    HTableDescriptor htd = new HTableDescriptor(tableName);
    htd.addFamily(new HColumnDescriptor(family1));
    htd.addFamily(new HColumnDescriptor(family2));
    htd.setOwner(USER_OWNER);
    admin.createTable(htd);

    List<UserPermission> perms;

    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      perms = ProtobufUtil.getUserPermissions(protocol, tableName);
    } finally {
      acl.close();
    }

    UserPermission ownerperm = new UserPermission(
      Bytes.toBytes(USER_OWNER.getName()), tableName, null, Action.values());
    assertTrue("Owner should have all permissions on table",
      hasFoundUserPermission(ownerperm, perms));

    User user = User.createUserForTesting(TEST_UTIL.getConfiguration(), "user", new String[0]);
    byte[] userName = Bytes.toBytes(user.getShortName());

    UserPermission up = new UserPermission(userName,
      tableName, family1, qualifier, Permission.Action.READ);
    assertFalse("User should not be granted permission: " + up.toString(),
      hasFoundUserPermission(up, perms));

    // grant read permission
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, user.getShortName(),
        tableName, family1, qualifier, Permission.Action.READ);
      perms = ProtobufUtil.getUserPermissions(protocol, tableName);
    } finally {
      acl.close();
    }

    UserPermission upToVerify = new UserPermission(
      userName, tableName, family1, qualifier, Permission.Action.READ);
    assertTrue("User should be granted permission: " + upToVerify.toString(),
      hasFoundUserPermission(upToVerify, perms));

    upToVerify = new UserPermission(
      userName, tableName, family1, qualifier, Permission.Action.WRITE);
    assertFalse("User should not be granted permission: " + upToVerify.toString(),
      hasFoundUserPermission(upToVerify, perms));

    // grant read+write
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.grant(protocol, user.getShortName(),
        tableName, family1, qualifier,
          Permission.Action.WRITE, Permission.Action.READ);
      perms = ProtobufUtil.getUserPermissions(protocol, tableName);
    } finally {
      acl.close();
    }

    upToVerify = new UserPermission(userName, tableName, family1,
      qualifier, Permission.Action.WRITE, Permission.Action.READ);
    assertTrue("User should be granted permission: " + upToVerify.toString(),
      hasFoundUserPermission(upToVerify, perms));

    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      ProtobufUtil.revoke(protocol, user.getShortName(), tableName, family1, qualifier,
        Permission.Action.WRITE, Permission.Action.READ);
      perms = ProtobufUtil.getUserPermissions(protocol, tableName);
    } finally {
      acl.close();
    }

    assertFalse("User should not be granted permission: " + upToVerify.toString(),
      hasFoundUserPermission(upToVerify, perms));

    // disable table before modification
    admin.disableTable(tableName);

    User newOwner = User.createUserForTesting(conf, "new_owner", new String[] {});
    htd.setOwner(newOwner);
    admin.modifyTable(tableName, htd);

    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(tableName);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      perms = ProtobufUtil.getUserPermissions(protocol, tableName);
    } finally {
      acl.close();
    }

    UserPermission newOwnerperm = new UserPermission(
      Bytes.toBytes(newOwner.getName()), tableName, null, Action.values());
    assertTrue("New owner should have all permissions on table",
      hasFoundUserPermission(newOwnerperm, perms));

    // delete table
    admin.deleteTable(tableName);
  }

  @Test
  public void testGlobalPermissionList() throws Exception {
    List<UserPermission> perms;
    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel service = acl.coprocessorService(HConstants.EMPTY_START_ROW);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(service);
      perms = ProtobufUtil.getUserPermissions(protocol, null);
    } finally {
      acl.close();
    }
    UserPermission adminPerm = new UserPermission(Bytes.toBytes(USER_ADMIN.getShortName()),
      AccessControlLists.ACL_TABLE_NAME, null, null, Bytes.toBytes("ACRW"));
    assertTrue("Only user admin has permission on table _acl_ per setup",
      perms.size() == 1 && hasFoundUserPermission(adminPerm, perms));
  }

  /** global operations */
  private void verifyGlobal(AccessTestAction action) throws Exception {
    verifyAllowed(action, SUPERUSER);

    verifyDenied(action, USER_CREATE, USER_RW, USER_NONE, USER_RO);
  }

  public void checkGlobalPerms(Permission.Action... actions) throws IOException {
    Permission[] perms = new Permission[actions.length];
    for (int i = 0; i < actions.length; i++) {
      perms[i] = new Permission(actions[i]);
    }
    CheckPermissionsRequest.Builder request = CheckPermissionsRequest.newBuilder();
    for (Action a : actions) {
      request.addPermission(AccessControlProtos.Permission.newBuilder()
          .addAction(ProtobufUtil.toPermissionAction(a)).build());
    }
    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel channel = acl.coprocessorService(new byte[0]);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(channel);
      try {
        protocol.checkPermissions(null, request.build());
      } catch (ServiceException se) {
        ProtobufUtil.toIOException(se);
      }
    } finally {
      acl.close();
    }
  }

  public void checkTablePerms(byte[] table, byte[] family, byte[] column,
      Permission.Action... actions) throws IOException {
    Permission[] perms = new Permission[actions.length];
    for (int i = 0; i < actions.length; i++) {
      perms[i] = new TablePermission(table, family, column, actions[i]);
    }

    checkTablePerms(table, perms);
  }

  public void checkTablePerms(byte[] table, Permission... perms) throws IOException {
    CheckPermissionsRequest.Builder request = CheckPermissionsRequest.newBuilder();
    for (Permission p : perms) {
      request.addPermission(ProtobufUtil.toPermission(p));
    }
    HTable acl = new HTable(conf, table);
    try {
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(acl.coprocessorService(new byte[0]));
      try {
        protocol.checkPermissions(null, request.build());
      } catch (ServiceException se) {
        ProtobufUtil.toIOException(se);
      }
    } finally {
      acl.close();
    }
  }

  @Test
  public void testCheckPermissions() throws Exception {
    // --------------------------------------
    // test global permissions
    AccessTestAction globalAdmin = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkGlobalPerms(Permission.Action.ADMIN);
        return null;
      }
    };
    // verify that only superuser can admin
    verifyGlobal(globalAdmin);

    // --------------------------------------
    // test multiple permissions
    AccessTestAction globalReadWrite = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkGlobalPerms(Permission.Action.READ, Permission.Action.WRITE);
        return null;
      }
    };

    verifyGlobal(globalReadWrite);

    // --------------------------------------
    // table/column/qualifier level permissions
    final byte[] TEST_Q1 = Bytes.toBytes("q1");
    final byte[] TEST_Q2 = Bytes.toBytes("q2");

    User userTable = User.createUserForTesting(conf, "user_check_perms_table", new String[0]);
    User userColumn = User.createUserForTesting(conf, "user_check_perms_family", new String[0]);
    User userQualifier = User.createUserForTesting(conf, "user_check_perms_q", new String[0]);

    HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel channel = acl.coprocessorService(new byte[0]);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(channel);
      ProtobufUtil.grant(protocol, userTable.getShortName(),
        TEST_TABLE, null, null, Permission.Action.READ);
      ProtobufUtil.grant(protocol, userColumn.getShortName(),
        TEST_TABLE, TEST_FAMILY, null, Permission.Action.READ);
      ProtobufUtil.grant(protocol, userQualifier.getShortName(),
        TEST_TABLE, TEST_FAMILY, TEST_Q1, Permission.Action.READ);
    } finally {
      acl.close();
    }

    AccessTestAction tableRead = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, null, null, Permission.Action.READ);
        return null;
      }
    };

    AccessTestAction columnRead = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, TEST_FAMILY, null, Permission.Action.READ);
        return null;
      }
    };

    AccessTestAction qualifierRead = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, TEST_FAMILY, TEST_Q1, Permission.Action.READ);
        return null;
      }
    };

    AccessTestAction multiQualifierRead = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, new Permission[] {
            new TablePermission(TEST_TABLE, TEST_FAMILY, TEST_Q1, Permission.Action.READ),
            new TablePermission(TEST_TABLE, TEST_FAMILY, TEST_Q2, Permission.Action.READ), });
        return null;
      }
    };

    AccessTestAction globalAndTableRead = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, new Permission[] { new Permission(Permission.Action.READ),
            new TablePermission(TEST_TABLE, null, (byte[]) null, Permission.Action.READ), });
        return null;
      }
    };

    AccessTestAction noCheck = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, new Permission[0]);
        return null;
      }
    };

    verifyAllowed(tableRead, SUPERUSER, userTable);
    verifyDenied(tableRead, userColumn, userQualifier);

    verifyAllowed(columnRead, SUPERUSER, userTable, userColumn);
    verifyDenied(columnRead, userQualifier);

    verifyAllowed(qualifierRead, SUPERUSER, userTable, userColumn, userQualifier);

    verifyAllowed(multiQualifierRead, SUPERUSER, userTable, userColumn);
    verifyDenied(multiQualifierRead, userQualifier);

    verifyAllowed(globalAndTableRead, SUPERUSER);
    verifyDenied(globalAndTableRead, userTable, userColumn, userQualifier);

    verifyAllowed(noCheck, SUPERUSER, userTable, userColumn, userQualifier);

    // --------------------------------------
    // test family level multiple permissions
    AccessTestAction familyReadWrite = new AccessTestAction() {
      @Override
      public Object run() throws Exception {
        checkTablePerms(TEST_TABLE, TEST_FAMILY, null, Permission.Action.READ,
          Permission.Action.WRITE);
        return null;
      }
    };

    verifyAllowed(familyReadWrite, SUPERUSER, USER_OWNER, USER_RW);
    verifyDenied(familyReadWrite, USER_NONE, USER_CREATE, USER_RO);

    // --------------------------------------
    // check for wrong table region
    CheckPermissionsRequest checkRequest = CheckPermissionsRequest.newBuilder()
      .addPermission(AccessControlProtos.Permission.newBuilder()
        .setTable(ByteString.copyFrom(TEST_TABLE))
        .addAction(AccessControlProtos.Permission.Action.CREATE)
      ).build();
    acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
    try {
      BlockingRpcChannel channel = acl.coprocessorService(new byte[0]);
      AccessControlService.BlockingInterface protocol =
        AccessControlService.newBlockingStub(channel);
      try {
        // but ask for TablePermissions for TEST_TABLE
        protocol.checkPermissions(null, checkRequest);
        fail("this should have thrown CoprocessorException");
      } catch (ServiceException ex) {
        // expected
      }
    } finally {
      acl.close();
    }
  }

  @Test
  public void testStopRegionServer() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preStopRegionServer(ObserverContext.createAndPrepare(RSCP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_OWNER, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testOpenRegion() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preOpen(ObserverContext.createAndPrepare(RCP_ENV, null));
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_OWNER);
  }

  @Test
  public void testCloseRegion() throws Exception {
    AccessTestAction action = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preClose(ObserverContext.createAndPrepare(RCP_ENV, null), false);
        return null;
      }
    };

    verifyAllowed(action, SUPERUSER, USER_ADMIN);
    verifyDenied(action, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_OWNER);
  }

  @Test
  public void testSnapshot() throws Exception {
    AccessTestAction snapshotAction = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preSnapshot(ObserverContext.createAndPrepare(CP_ENV, null),
          null, null);
        return null;
      }
    };

    AccessTestAction deleteAction = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preDeleteSnapshot(ObserverContext.createAndPrepare(CP_ENV, null),
          null);
        return null;
      }
    };

    AccessTestAction restoreAction = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preRestoreSnapshot(ObserverContext.createAndPrepare(CP_ENV, null),
          null, null);
        return null;
      }
    };

    AccessTestAction cloneAction = new AccessTestAction() {
      public Object run() throws Exception {
        ACCESS_CONTROLLER.preCloneSnapshot(ObserverContext.createAndPrepare(CP_ENV, null),
          null, null);
        return null;
      }
    };

    verifyAllowed(snapshotAction, SUPERUSER, USER_ADMIN);
    verifyDenied(snapshotAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_OWNER);

    verifyAllowed(cloneAction, SUPERUSER, USER_ADMIN);
    verifyDenied(deleteAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_OWNER);

    verifyAllowed(restoreAction, SUPERUSER, USER_ADMIN);
    verifyDenied(restoreAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_OWNER);

    verifyAllowed(deleteAction, SUPERUSER, USER_ADMIN);
    verifyDenied(cloneAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_OWNER);
  }

  @Test
  public void testCellPermissions() throws Exception {
    // table/column/qualifier level permissions
    final byte[] TEST_ROW = Bytes.toBytes("cellpermtest");
    final byte[] TEST_Q1 = Bytes.toBytes("q1");
    final byte[] TEST_Q2 = Bytes.toBytes("q2");
    final byte[] TEST_Q3 = Bytes.toBytes("q3");
    final byte[] TEST_Q4 = Bytes.toBytes("q4");
    // test value
    final byte[] ZERO = Bytes.toBytes(0L);

    /* ---- Setup ---- */

    // additional test user
    final User userOther = User.createUserForTesting(conf, "user_check_cell_perms_other",
      new String[0]);

    // store two sets of values, one store with a cell level ACL, and one without
    verifyAllowed(new AccessTestAction() {
      public Object run() throws Exception {
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          Put p;
          // with ro ACL
          p = new Put(TEST_ROW).add(TEST_FAMILY, TEST_Q1, ZERO);
          ProtobufUtil.setMutationACL(p, new UserTablePermissions()
            .add(userOther, new TablePermission(Permission.Action.READ)));
          t.put(p);
         // with rw ACL
         p = new Put(TEST_ROW).add(TEST_FAMILY, TEST_Q2, ZERO);
          ProtobufUtil.setMutationACL(p, new UserTablePermissions()
            .add(userOther, new TablePermission(Permission.Action.READ,
              Permission.Action.WRITE)));
          t.put(p);
          // no ACL
          p = new Put(TEST_ROW)
            .add(TEST_FAMILY, TEST_Q3, ZERO)
            .add(TEST_FAMILY, TEST_Q4, ZERO);
          t.put(p);
        } finally {
          t.close();
        }
        return null;
      }
    }, USER_OWNER);

    /* ---- Gets ---- */

    AccessTestAction getQ1 = new AccessTestAction() {
      public Object run() throws Exception {
        Get get = new Get(TEST_ROW).addColumn(TEST_FAMILY, TEST_Q1);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          return t.get(get).list();
        } finally {
          t.close();
        }
      }
    };

    AccessTestAction getQ2 = new AccessTestAction() {
      public Object run() throws Exception {
        Get get = new Get(TEST_ROW).addColumn(TEST_FAMILY, TEST_Q2);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          return t.get(get).list();
        } finally {
          t.close();
        }
      }
    };

    AccessTestAction getQ3 = new AccessTestAction() {
      public Object run() throws Exception {
        Get get = new Get(TEST_ROW).addColumn(TEST_FAMILY, TEST_Q3);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          return t.get(get).list();
        } finally {
          t.close();
        }
      }
    };

    AccessTestAction getQ4 = new AccessTestAction() {
      public Object run() throws Exception {
        Get get = new Get(TEST_ROW).addColumn(TEST_FAMILY, TEST_Q4);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          return t.get(get).list();
        } finally {
          t.close();
        }
      }
    };

    // Confirm special read access set at cell level

    verifyAllowed(getQ1, userOther);
    verifyAllowed(getQ2, userOther);

    // Confirm this access does not extend to other cells

    verifyDenied(getQ3, userOther);
    verifyDenied(getQ4, userOther);

    /* ---- Scans ---- */

    // check that a scan over the test data returns the expected number of KVs

    final List<KeyValue> scanResults = new ArrayList<KeyValue>();

    AccessTestAction scanAction = new AccessTestAction() {
      public List<KeyValue> run() throws Exception {
        Scan scan = new Scan();
        scan.setStartRow(TEST_ROW);
        scan.setStopRow(Bytes.add(TEST_ROW, new byte[]{ 0 } ));
        scan.addFamily(TEST_FAMILY);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          ResultScanner scanner = t.getScanner(scan);
          Result result = null;
          do {
            result = scanner.next();
            if (result != null) {
              scanResults.addAll(result.list());
            }
          } while (result != null);
        } finally {
          t.close();
        }
        return scanResults;
      }
    };

    // owner will see all values
    scanResults.clear();
    verifyAllowed(scanAction, USER_OWNER);
    assertEquals(4, scanResults.size());

    // other user will see 2 values
    scanResults.clear();
    verifyAllowed(scanAction, userOther);
    assertEquals(2, scanResults.size());

    /* ---- Increments ---- */

    AccessTestAction incrementQ1 = new AccessTestAction() {
      public Object run() throws Exception {
        Increment i = new Increment(TEST_ROW).addColumn(TEST_FAMILY, TEST_Q1, 1L);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.increment(i);
        } finally {
          t.close();
        }
        return null;
      }
    };

    AccessTestAction incrementQ2 = new AccessTestAction() {
      public Object run() throws Exception {
        Increment i = new Increment(TEST_ROW).addColumn(TEST_FAMILY, TEST_Q2, 1L);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.increment(i);
        } finally {
          t.close();
        }
        return null;
      }
    };

    verifyDenied(incrementQ1, userOther);
    verifyAllowed(incrementQ1, USER_OWNER);
    verifyAllowed(incrementQ2, userOther);

    /* ---- Deletes ---- */

    AccessTestAction deleteFamily = new AccessTestAction() {
      public Object run() throws Exception {
        Delete delete = new Delete(TEST_ROW).deleteFamily(TEST_FAMILY);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.delete(delete);
        } finally {
          t.close();
        }
        return null;
      }
    };

    AccessTestAction deleteQ1 = new AccessTestAction() {
      public Object run() throws Exception {
        Delete delete = new Delete(TEST_ROW).deleteColumn(TEST_FAMILY, TEST_Q1);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.delete(delete);
        } finally {
          t.close();
        }
        return null;
      }
    };

    AccessTestAction deleteQ2 = new AccessTestAction() {
      public Object run() throws Exception {
        Delete delete = new Delete(TEST_ROW).deleteColumn(TEST_FAMILY, TEST_Q2);
        HTable t = new HTable(conf, TEST_TABLE);
        try {
          t.delete(delete);
        } finally {
          t.close();
        }
        return null;
      }
    };

    verifyDenied(deleteFamily, userOther);
    verifyDenied(deleteQ1, userOther);
    verifyAllowed(deleteQ1, USER_OWNER);
    verifyAllowed(deleteQ2, userOther);
  }

  @Test
  public void testGrantRevoke() throws Exception {

    AccessTestAction grantAction = new AccessTestAction() {
      public Object run() throws Exception {
        HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
        try {
          BlockingRpcChannel service = acl.coprocessorService(TEST_TABLE);
          AccessControlService.BlockingInterface protocol =
            AccessControlService.newBlockingStub(service);
          ProtobufUtil.grant(protocol, USER_RO.getShortName(), TEST_TABLE,
            TEST_FAMILY, null, Action.READ);
        } finally {
          acl.close();
        }
        return null;
      }
    };

    AccessTestAction revokeAction = new AccessTestAction() {
      public Object run() throws Exception {
        HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
        try {
          BlockingRpcChannel service = acl.coprocessorService(TEST_TABLE);
          AccessControlService.BlockingInterface protocol =
            AccessControlService.newBlockingStub(service);
          ProtobufUtil.revoke(protocol, USER_RO.getShortName(), TEST_TABLE,
            TEST_FAMILY, null, Action.READ);
        } finally {
          acl.close();
        }
        return null;
      }
    };

    AccessTestAction getPermissionsAction = new AccessTestAction() {
      public Object run() throws Exception {
        HTable acl = new HTable(conf, AccessControlLists.ACL_TABLE_NAME);
        try {
          BlockingRpcChannel service = acl.coprocessorService(TEST_TABLE);
          AccessControlService.BlockingInterface protocol =
            AccessControlService.newBlockingStub(service);
          ProtobufUtil.getUserPermissions(protocol, TEST_TABLE);
        } finally {
          acl.close();
        }
        return null;
      }
    };

    verifyAllowed(grantAction, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(grantAction, USER_CREATE, USER_RW, USER_RO, USER_NONE);

    verifyAllowed(revokeAction, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(revokeAction, USER_CREATE, USER_RW, USER_RO, USER_NONE);

    verifyAllowed(getPermissionsAction, SUPERUSER, USER_ADMIN, USER_OWNER);
    verifyDenied(getPermissionsAction, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }

  @Test
  public void testACLCFProtection() throws Exception {
    AccessTestAction addACLCFAction = new AccessTestAction() {
      public Object run() throws Exception {
        HBaseAdmin admin = new HBaseAdmin(TEST_UTIL.getConfiguration());
        try {
          admin.disableTable(TEST_TABLE);
          try {
            admin.addColumn(TEST_TABLE, AccessControlLists.ACL_COLUMNDESC);
          } finally {
            admin.enableTable(TEST_TABLE);
          }
        } finally {
          admin.close();
        }
        return null;
      }
    };

    AccessTestAction modifyACLCFAction = new AccessTestAction() {
      public Object run() throws Exception {
        HBaseAdmin admin = new HBaseAdmin(TEST_UTIL.getConfiguration());
        try {
          admin.disableTable(TEST_TABLE);
          try {
            admin.modifyColumn(TEST_TABLE, AccessControlLists.ACL_COLUMNDESC);
          } finally {
            admin.enableTable(TEST_TABLE);
          }
        } finally {
          admin.close();
        }
        return null;
      }
    };

    AccessTestAction deleteACLCFAction = new AccessTestAction() {
      public Object run() throws Exception {
        HBaseAdmin admin = new HBaseAdmin(TEST_UTIL.getConfiguration());
        try {
          admin.disableTable(TEST_TABLE);
          try {
            admin.deleteColumn(TEST_TABLE, AccessControlLists.ACL_CF_NAME);
          } finally {
            admin.enableTable(TEST_TABLE);
          }
        } finally {
          admin.close();
        }
        return null;
      }
    };

    // We need to interleave tests for delete and add
    verifyDenied(deleteACLCFAction, USER_CREATE, USER_RW, USER_RO, USER_NONE);
    verifyAllowed(deleteACLCFAction, SUPERUSER);
    verifyAllowed(addACLCFAction, SUPERUSER);
    verifyAllowed(deleteACLCFAction, USER_ADMIN);
    verifyAllowed(addACLCFAction, USER_ADMIN);
    verifyDenied(addACLCFAction, USER_CREATE, USER_RW, USER_RO, USER_NONE);

    verifyAllowed(modifyACLCFAction, SUPERUSER, USER_ADMIN);
    verifyDenied(modifyACLCFAction, USER_CREATE, USER_RW, USER_RO, USER_NONE);
  }
}
