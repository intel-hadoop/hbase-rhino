/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.apache.hadoop.hbase.security.access;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.LargeTests;
import org.apache.hadoop.hbase.client.HTable;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.io.encoding.DataBlockEncoding;
import org.apache.hadoop.hbase.protobuf.ProtobufUtil;
import org.apache.hadoop.hbase.security.SecureTestUtil;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.util.MultiThreadedWriter;
import org.apache.hadoop.hbase.util.Pair;
import org.apache.hadoop.hbase.util.TestMiniClusterLoadParallel;
import org.apache.hadoop.hbase.util.test.LoadTestDataGenerator;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@Category(LargeTests.class)
@RunWith(Parameterized.class)
public class TestCellACLsLoadTest extends TestMiniClusterLoadParallel {
  static final Log LOG = LogFactory.getLog(TestCellACLsLoadTest.class);
  static final Random RNG = new Random();

  static final int TIMEOUT_MS = 600000;

  final double aclProbability;
  final int minACLSize;
  final int maxACLSize;
  final Pair<User,TablePermission>[] userPerms;

  @Parameters
  public static Collection<Object[]> parameters() {
    List<Object[]> parameters = new ArrayList<Object[]>();
    parameters.add(new Object[]{ 0.0,  0,  0 }); // baseline
    parameters.add(new Object[]{ 0.1,  2,  5 }); // 10% of cells, 2-5 entries per ACL
    parameters.add(new Object[]{ 0.3,  3,  7 }); // 30% of cells, 3-7 entries per ACL
    parameters.add(new Object[]{ 0.5,  5, 10 }); // 50% of cells, 5-10 entries per ACL
    parameters.add(new Object[]{ 0.8, 10, 20 }); // 80% of cells, 10-20 entries per ACL
    return parameters;
  }

  public TestCellACLsLoadTest(double aclProbability, int minACLSize, int maxACLSize)
      throws IOException {
    super(false, DataBlockEncoding.NONE);
    this.aclProbability = aclProbability;
    this.minACLSize = minACLSize;
    this.maxACLSize = maxACLSize;

    // By default the block cache is 25% of heap, lower this to 5% to simulate
    // heap pressure under real world conditions, and resulting increased IO
    conf.setFloat("hfile.block.cache.size", 0.05f);

    // Create the set of test users
    userPerms = new Pair[maxACLSize];
    for (int i = 0; i < maxACLSize; i++) {
      List<Permission.Action> actions = new ArrayList<Permission.Action>();
      actions.add(Permission.Action.READ); // Always include at least one perm
      if (RNG.nextBoolean()) actions.add(Permission.Action.CREATE);
      if (RNG.nextBoolean()) actions.add(Permission.Action.ADMIN);
      if (RNG.nextBoolean()) actions.add(Permission.Action.WRITE);
      userPerms[i] = new Pair<User,TablePermission>(
        User.createUserForTesting(conf, String.format("user%d",  i), new String[0]),
        new TablePermission(actions.toArray(new Permission.Action[actions.size()])));
    }

    // Enable security
    SecureTestUtil.enableSecurity(conf);

    // We seem to need this too so we avoid HDFS shortcutting access exception
    String baseuser = User.getCurrent().getShortName();
    conf.set("hbase.superuser", conf.get("hbase.superuser", "") +
      String.format(",%s.hfs.0,%s.hfs.1,%s.hfs.2", baseuser, baseuser, baseuser));
  }

  @Before
  public void setUp() throws Exception {
    super.setUp();
    // Wait for the ACL table to become available
    TEST_UTIL.waitTableAvailable(AccessControlLists.ACL_TABLE_NAME, 5000);
  }

  @Override
  protected MultiThreadedWriter prepareWriterThreads(LoadTestDataGenerator dataGen,
      Configuration conf, byte[] table) {
    MultiThreadedWriter writer = new MultiThreadedWriter(dataGen, conf, table) {
      AtomicLong numCells = new AtomicLong(0);
      AtomicLong numCellsWithACLs = new AtomicLong(0);

      @Override
      public void insert(HTable table, Put put, long keyBase) {
        if (RNG.nextDouble() < aclProbability) {
          int numACLs = RNG.nextInt(maxACLSize);
          if (numACLs < minACLSize) {
            numACLs = minACLSize;
          }
          UserTablePermissions perms = new UserTablePermissions();
          for (int i = 0; i < numACLs; i++) {
            perms.add(userPerms[i].getFirst(), userPerms[i].getSecond());
          }
          ProtobufUtil.setMutationACL(put, perms);
          numCellsWithACLs.incrementAndGet();
        }
        numCells.incrementAndGet();
        super.insert(table, put, keyBase);
      }

      @Override
      protected String progressInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.progressInfo());
        appendToStatus(sb, "cells", numCells.get());
        appendToStatus(sb, "cellsWithACLs", String.format("%d (%.2f%%)",
          numCellsWithACLs.get(),
          100.0 * ((double)numCellsWithACLs.get() / (double)numCells.get())));
        return sb.toString();
      }

    };
    writer.setMultiPut(isMultiPut);
    return writer;
  }

  @Override
  protected void prepareForLoadTest() throws IOException {
    LOG.info("Starting load test: aclProbability=" + aclProbability +
        ", minACLSize=" + minACLSize + ", maxACLSize=" + maxACLSize);
    super.prepareForLoadTest();
  }

  @Test(timeout=TIMEOUT_MS)
  public void loadTest() throws Exception {
    LOG.info("******************************************************************************");
    super.loadTest();
    LOG.info("******************************************************************************");
  }
}
