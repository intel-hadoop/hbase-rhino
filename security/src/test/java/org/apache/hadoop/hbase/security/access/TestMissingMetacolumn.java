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

import static org.junit.Assert.*;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.MediumTests;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.security.SecureTestUtil;
import org.apache.hadoop.hbase.util.Bytes;

import org.junit.experimental.categories.Category;
import org.junit.Test;

@Category(MediumTests.class)
public class TestMissingMetacolumn {
  private static HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();

  private static byte[] TABLE = Bytes.toBytes("testtable");
  private static byte[] FAMILY = Bytes.toBytes("test");

  @Test
  public void testMissingMetacolumn() throws Exception {
    // Create a test cluster
    TEST_UTIL.startMiniCluster();
    TEST_UTIL.createTable(TABLE, FAMILY);
    TEST_UTIL.waitTableAvailable(TABLE, 5000);

    // Create test table, won't have the ACL CF
    HBaseAdmin admin = TEST_UTIL.getHBaseAdmin();
    assertNotNull(admin.getTableDescriptor(TABLE).getFamily(FAMILY));
    assertNull(admin.getTableDescriptor(TABLE).getFamily(AccessControlLists.ACL_CF_NAME));

    // Restart with security enabled
    TEST_UTIL.shutdownMiniHBaseCluster();
    Configuration conf = TEST_UTIL.getConfiguration();
    SecureTestUtil.enableSecurity(conf);
    TEST_UTIL.restartHBaseCluster(1);
    TEST_UTIL.waitTableAvailable(AccessControlLists.ACL_TABLE_NAME, 30000); // wait for processing
    TEST_UTIL.waitTableAvailable(TABLE, 5000);

    // Was the ACL CF added?
    admin = TEST_UTIL.getHBaseAdmin();
    assertNotNull(admin.getTableDescriptor(TABLE).getFamily(FAMILY));
    assertNotNull(admin.getTableDescriptor(TABLE).getFamily(AccessControlLists.ACL_CF_NAME));

    // Clean up
    TEST_UTIL.shutdownMiniCluster();
  }
}
