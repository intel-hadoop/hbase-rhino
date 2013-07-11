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

package org.apache.hadoop.hbase.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.MediumTests;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.util.Bytes;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(MediumTests.class)
public class TestEncryptedHTable {
  private static final Log LOG = LogFactory.getLog(TestEncryptedHTable.class);

  static final byte[] TABLE = Bytes.toBytes("testFactory");
  static final byte[] FAMILY = Bytes.toBytes("family");
  static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  static boolean inited = false;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    Configuration conf = TEST_UTIL.getConfiguration();

    // Check if we can load the encryption codec
    Encryption.Context context = Encryption.newContext(conf);
    context.setAlgorithm(Encryption.Algorithm.AES);
    if (!Encryption.isEncryptionCodecAvailable(context)) {
      LOG.warn("Crypto codec cannot be loaded");
      return;
    }

    conf.set(HConstants.CRYPTO_KEYPROVIDER_CONF_KEY,
      "org.apache.hadoop.io.crypto.KeyProviderForTesting");
    conf.set(HConstants.CRYPTO_KEYPROVIDER_PARAMETERS_KEY, "123456");
    TEST_UTIL.startMiniCluster();
    inited = true;
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    if (inited) {
      TEST_UTIL.shutdownMiniCluster();
    }
  }

  // Basic tests

  @Test
  public void testEncryption() throws Exception {
    if (!inited) {
      LOG.warn("testEncryption skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testEncryption");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("value");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t1 = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t1.put(new Put(ROW).add(FAMILY, QUALIFIER, VALUE));
      byte[] data = t1.get(new Get(ROW)).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE));
    } finally {
      t1.close();
    }
    // With plain HTable
    HTableInterface t2 = new HTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      byte[] data = t2.get(new Get(ROW)).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertFalse(Bytes.equals(data, VALUE));
    } finally {
      t2.close();
    }
    Configuration badConf = HBaseConfiguration.create(TEST_UTIL.getConfiguration());
    badConf.set(HConstants.CRYPTO_KEYPROVIDER_PARAMETERS_KEY, "654321");
    // With incorrect key
    HTableInterface t3 = new EncryptedHTable(badConf, TABLE);
    try {
      byte[] data = t3.get(new Get(ROW)).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertFalse(Bytes.equals(data, VALUE));
    } catch (IOException e) {
      // IOException is ok too
    } finally {
      t3.close();
    }
  }

  @Test
  public void testSelectiveEncryption() throws Exception {
    if (!inited) {
      LOG.warn("testSelectiveEncryption skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testSelectiveEncryption");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[][] FAMILIES = new byte[][] {
      Bytes.toBytes("f1"), Bytes.toBytes("f2")
    };
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[][] VALUE = new byte[][] { 
      Bytes.toBytes("value1"), Bytes.toBytes("value2")
    };
    TEST_UTIL.createTable(TABLE, FAMILIES).close();
    EncryptedHTable t1 = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    t1.addFamily(FAMILIES[0]);
    try {
      t1.put(new Put(ROW)
        .add(FAMILIES[0], QUALIFIER, VALUE[0])
        .add(FAMILIES[1], QUALIFIER, VALUE[1]));
      byte[] data = t1.get(new Get(ROW)).getValue(FAMILIES[0], QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[0]));
      data = t1.get(new Get(ROW)).getValue(FAMILIES[1], QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
    } finally {
      t1.close();
    }
    // With plain HTable
    HTableInterface t2 = new HTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      byte[] data = t2.get(new Get(ROW)).getValue(FAMILIES[0], QUALIFIER);
      assertNotNull(data);
      assertFalse(Bytes.equals(data, VALUE[0]));
      data = t1.get(new Get(ROW)).getValue(FAMILIES[1], QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
    } finally {
      t2.close();
    }
  }

  // HTableInterface testers

  @Test
  public void testGet() throws Exception {
    if (!inited) {
      LOG.warn("testGet skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testGet");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("value");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.put(new Put(ROW).add(FAMILY, QUALIFIER, VALUE));
      byte[] data = t.get(new Get(ROW)).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE));
    } finally {
      t.close();
    }
  }

  @Test
  public void testGetWithList() throws Exception {
    if (!inited) {
      LOG.warn("testGetWithList skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testGetWithList");
    final byte[][] ROW = new byte[][] {
      Bytes.toBytes("row1"), Bytes.toBytes("row2"),
    };
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[][] VALUE = new byte[][] {
      Bytes.toBytes("a"), Bytes.toBytes("This is a test!"),
    };
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.put(new Put(ROW[0]).add(FAMILY, QUALIFIER, VALUE[0]));
      t.put(new Put(ROW[1]).add(FAMILY, QUALIFIER, VALUE[1]));
      List<Get> gets = new ArrayList<Get>(2);
      gets.add(new Get(ROW[0]));
      gets.add(new Get(ROW[1]));
      Result[] results = t.get(gets);
      assertNotNull(results);
      assertEquals(results.length, 2);
      assertNotNull(results[0]);
      assertNotNull(results[1]);
      byte[] data1 = results[0].getValue(FAMILY, QUALIFIER);
      byte[] data2 = results[1].getValue(FAMILY, QUALIFIER);
      assertTrue(Bytes.equals(data1, VALUE[0]));
      assertTrue(Bytes.equals(data2, VALUE[1]));
    } finally {
      t.close();
    }
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testGetRowOrBefore() throws Exception {
    if (!inited) {
      LOG.warn("testGetRowOrBefore skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testGetRowOrBefore");
    final byte[][] ROW = new byte[][] { 
      Bytes.toBytes("a"), Bytes.toBytes("b"), Bytes.toBytes("c"), Bytes.toBytes("d"),
      Bytes.toBytes("e")
    };
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[][] VALUE = new byte[][] {
      Bytes.toBytes("v1"), Bytes.toBytes("This is a test!")
    };
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.put(new Put(ROW[1]).add(FAMILY, QUALIFIER, VALUE[0]));
      t.put(new Put(ROW[3]).add(FAMILY, QUALIFIER, VALUE[1]));
      Result r = null;
      // Test before first that null is returned
      r = t.getRowOrBefore(ROW[0], FAMILY);
      assertNull(r);
      // Test at first that first is returned
      r = t.getRowOrBefore(ROW[1], FAMILY);
      assertNotNull(r);
      byte[] data = r.getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[0]));
      // Test in between first and second that first is returned
      r = t.getRowOrBefore(ROW[2], FAMILY);
      assertNotNull(r);
      data = r.getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[0]));
      // Test at second make sure second is returned
      r = t.getRowOrBefore(ROW[3], FAMILY);
      assertNotNull(r);
      data = r.getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
      // Test after second, make sure second is returned
      r = t.getRowOrBefore(ROW[4], FAMILY);
      assertNotNull(r);
      data = r.getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
    } finally {
      t.close();
    }
  }

  @Test
  public void testScanner() throws Exception {
    if (!inited) {
      LOG.warn("testScanner skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testScanner");
    final byte[][] ROW = new byte[][] { 
      Bytes.toBytes("a"), Bytes.toBytes("b"), Bytes.toBytes("c"), Bytes.toBytes("d"),
      Bytes.toBytes("e")
    };
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[][] VALUE = new byte[][] {
      Bytes.toBytes("v1"), Bytes.toBytes("This is a test!"), Bytes.toBytes("value3"),
      Bytes.toBytes("v4"), Bytes.toBytes("This is another test!")
    };
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      for (int i = 0; i < ROW.length; i++) {
        t.put(new Put(ROW[i]).add(FAMILY, QUALIFIER, VALUE[i]));
      }
    } finally {
      t.close();
    }
    t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      ResultScanner s;
      s = t.getScanner(new Scan());
      try {
        for (int i = 0; i < ROW.length; i++) {
          Result r = s.next();
          assertNotNull(r);
          byte[] data = r.getValue(FAMILY, QUALIFIER);
          assertNotNull(data);
          assertTrue(Bytes.equals(data, VALUE[i]));
        }
        // Try to get one more
        Result r = s.next();
        assertNull(r);
      } finally {
        s.close();
      }
      s = t.getScanner(new Scan());
      try {
        Result[] results = s.next(ROW.length);
        assertNotNull(results);
        assertEquals(results.length, ROW.length);
        for (int i = 0; i < ROW.length; i++) {
          assertNotNull(results[i]);
          byte[] data = results[i].getValue(FAMILY, QUALIFIER);
          assertNotNull(data);
          assertTrue(Bytes.equals(data, VALUE[i]));
        }
      } finally {
        s.close();
      }
    } finally {
      t.close();
    }
  }

  @Test
  public void testPut() throws Exception {
    if (!inited) {
      LOG.warn("testPut skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testPut");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("value");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.put(new Put(ROW).add(FAMILY, QUALIFIER, VALUE));
      byte[] data = t.get(new Get(ROW)).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE));
    } finally {
      t.close();
    }
  }

  @Test
  public void testPutWithList() throws Exception {
    if (!inited) {
      LOG.warn("testPutWithList skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testPutWithList");
    final byte[][] ROW = new byte[][] {
      Bytes.toBytes("row1"), Bytes.toBytes("row2"),
    };
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[][] VALUE = new byte[][] {
      Bytes.toBytes("a"), Bytes.toBytes("This is a test!"),
    };
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      List<Put> puts = new ArrayList<Put>(2);
      puts.add(new Put(ROW[0]).add(FAMILY, QUALIFIER, VALUE[0]));
      puts.add(new Put(ROW[1]).add(FAMILY, QUALIFIER, VALUE[1]));
      t.put(puts);
      byte[] data = t.get(new Get(ROW[0])).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[0]));
      data = t.get(new Get(ROW[1])).getValue(FAMILY, QUALIFIER);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
    } finally {
      t.close();
    }
  }

  @Test
  public void testCheckAndPut() throws Exception {
    if (!inited) {
      LOG.warn("testCheckAndPut skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testCheckAndPut");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("value");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.checkAndPut(ROW, FAMILY, QUALIFIER, VALUE, new Put(ROW).add(FAMILY, QUALIFIER, VALUE));
      fail("checkAndPut did not throw UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      // Pass
    } finally {
      t.close();
    }
  }

  @Test
  public void testDelete() throws Exception {
    // We do not override delete
  }

  @Test
  public void testDeleteWithList() throws Exception {
    // We do not override delete
  }

  @Test
  public void testCheckAndDelete() throws Exception {
    if (!inited) {
      LOG.warn("testCheckAndDelete skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testCheckAndDelete");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("value");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.checkAndDelete(ROW, FAMILY, QUALIFIER, VALUE, new Delete(ROW));
      fail("checkAndDelete did not throw UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      // Pass
    } finally {
      t.close();
    }
  }

  @Test
  public void testMutateRow() throws Exception {
    if (!inited) {
      LOG.warn("testMutateRow skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testMutateRow");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[][] QUALIFIER = new byte[][] {
        Bytes.toBytes("q1"), Bytes.toBytes("q2")
    };
    final byte[][] VALUE = new byte[][] {
      Bytes.toBytes("value1"), Bytes.toBytes("value2")
    };
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      RowMutations rm = new RowMutations(ROW);
      rm.add(new Put(ROW).add(FAMILY, QUALIFIER[0], VALUE[0]));
      rm.add(new Put(ROW).add(FAMILY, QUALIFIER[1], VALUE[1]));
      t.mutateRow(rm);
      Result r = t.get(new Get(ROW));
      assertNotNull(r);
      byte[] data = r.getValue(FAMILY, QUALIFIER[0]);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[0]));
      data = r.getValue(FAMILY, QUALIFIER[1]);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
      rm = new RowMutations(ROW);
      rm.add(new Delete(ROW).deleteColumn(FAMILY, QUALIFIER[0]));
      t.mutateRow(rm);
      r = t.get(new Get(ROW));
      assertNotNull(r);
      data = r.getValue(FAMILY, QUALIFIER[0]);
      assertNull(data);
      data = r.getValue(FAMILY, QUALIFIER[1]);
      assertNotNull(data);
      assertTrue(Bytes.equals(data, VALUE[1]));
    } finally {
      t.close();
    }
  }

  @Test
  public void testAppend() throws Exception {
    if (!inited) {
      LOG.warn("testAppend skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testAppend");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("value");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.append(new Append(ROW).add(FAMILY, QUALIFIER, VALUE));
      fail("Append did not throw UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      // Pass
    } finally {
      t.close();
    }
  }

  @Test
  public void testIncrement() throws Exception {
    if (!inited) {
      LOG.warn("testIncrement skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testIncrement");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.increment(new Increment(ROW).addColumn(FAMILY, QUALIFIER, 1));
      fail("Increment did not throw UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      // Pass
    } finally {
      t.close();
    }
  }

  @Test
  public void testIncrementColumnValue() throws Exception {
    if (!inited) {
      LOG.warn("testIncrementColumnValue skipped");
    }

    final byte[] TABLE = Bytes.toBytes("testIncrementColumnValue");
    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    TEST_UTIL.createTable(TABLE, FAMILY).close();
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.incrementColumnValue(ROW, FAMILY, QUALIFIER, 1);
      fail("incrementColumnValue did not throw UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      // Pass
    } finally {
      t.close();
    }
  }

}
