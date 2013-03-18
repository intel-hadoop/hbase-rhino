/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.regionserver;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.MediumTests;
import org.apache.hadoop.hbase.Waiter.Predicate;
import org.apache.hadoop.hbase.client.HTable;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.io.hfile.CacheConfig;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.util.Bytes;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(MediumTests.class)
public class TestEncryptionKeyRotation {
  private static final Log LOG = LogFactory.getLog(TestEncryptionKeyRotation.class);
  private static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  private static boolean inited = false;
  private static Configuration conf = TEST_UTIL.getConfiguration();
  private static byte[] initialCFKey;
  private static byte[] secondCFKey;
  private static HTableDescriptor htd;

  private static List<Path> findStorefilePaths(byte[] tableName) throws Exception {
    List<Path> paths = new ArrayList<Path>();
    for (HRegion region:
        TEST_UTIL.getRSForFirstRegionInTable(tableName).getOnlineRegions(tableName)) {
      for (Store store: region.getStores().values()) {
        for (StoreFile storefile: store.getStorefiles()) {
          paths.add(storefile.getPath());
        }
      }
    }
    return paths;
  }

  private static byte[] extractHFileKey(Path path) throws Exception {
    HFile.Reader reader = HFile.createReader(TEST_UTIL.getTestFileSystem(), path,
      new CacheConfig(conf));
    try {
      reader.loadFileInfo();
      Encryption.Context context = reader.getCryptoContext();
      assertNotNull(context);
      return context.getKeyBytes();
    } finally {
      reader.close();
    }
  }

  @BeforeClass
  public static void setUp() throws Exception {
    Encryption.injectProviderForTesting();

    // Enable online schema updates
    conf.setBoolean("hbase.online.schema.update.enable", true);

    // Create the test encryption keys
    Encryption.Context context = Encryption.newContext(conf);
    context.setAlgorithm(Encryption.Algorithm.AES);
    if (Encryption.getEncryptionCodec(context) == null) {
      LOG.warn("Not setting up because encryption codec not loaded");
      return;
    }
    context.setKey("123456");
    initialCFKey = context.getKeyBytes();
    context.setKey("654321");
    secondCFKey = context.getKeyBytes();

    // Create the table schema
    htd = new HTableDescriptor("TestEncryptionKeyRotation");
    HColumnDescriptor hcd = new HColumnDescriptor("cf");
    hcd.setEncryptionType(Encryption.Algorithm.AES);
    hcd.setEncryptionKey(conf, initialCFKey);
    htd.addFamily(hcd);

    // Start the minicluster
    TEST_UTIL.startMiniCluster(1);

    inited = true;

    // Create the test table
    TEST_UTIL.getHBaseAdmin().createTable(htd);
    TEST_UTIL.waitTableAvailable(htd.getName(), 5000);

    // Create a store file
    HTable table = new HTable(conf, htd.getName());
    try {
      table.put(new Put(Bytes.toBytes("testrow"))
        .add(hcd.getName(), Bytes.toBytes("q"), Bytes.toBytes("value")));
    } finally {
      table.close();
    }
    TEST_UTIL.getHBaseAdmin().flush(htd.getName());
  }

  @AfterClass
  public static void tearDown() throws Exception {
    if (!inited) {
      return;
    }
    TEST_UTIL.shutdownMiniCluster();
  }

  @Test
  public void testKeyRotation() throws Exception {
    if (!inited) {
      LOG.warn("testKeyRotation skipped");
      return;
    }

    // Verify we have store file(s) with the initial key
    final List<Path> initialPaths = findStorefilePaths(htd.getName());
    assertTrue(initialPaths.size() > 0);
    for (Path path: initialPaths) {
      assertTrue("Store file " + path + " has incorrect key",
        Bytes.equals(initialCFKey, extractHFileKey(path)));
    }

    // Update the schema with a new encryption key
    HColumnDescriptor hcd = htd.getFamily(Bytes.toBytes("cf"));
    hcd.setEncryptionKey(conf, secondCFKey);
    TEST_UTIL.getHBaseAdmin().modifyColumn(htd.getName(), hcd);
    Thread.sleep(5000); // TODO: Need a predicate for online schema change
    
    // And major compact
    TEST_UTIL.getHBaseAdmin().majorCompact(htd.getName());
    TEST_UTIL.waitFor(30000, 1000, true, new Predicate<Exception>() {
      @Override
      public boolean evaluate() throws Exception {
        // When compaction has finished, all of the original files will be
        // gone
        boolean found = false;
        for (Path path: initialPaths) {
          found = TEST_UTIL.getTestFileSystem().exists(path);
          if (found) {
            LOG.info("Found " + path);
            break;
          }
        }
        return !found;
      }
    });

    // Verify we have store file(s) with only the new key
    List<Path> pathsAfterCompaction = findStorefilePaths(htd.getName());
    assertTrue(pathsAfterCompaction.size() > 0);
    for (Path path: pathsAfterCompaction) {
      assertFalse("Store file " + path + " retains initial key",
        Bytes.equals(initialCFKey, extractHFileKey(path)));
      assertTrue("Store file " + path + " has incorrect key",
        Bytes.equals(secondCFKey, extractHFileKey(path)));
    }
  }

}
