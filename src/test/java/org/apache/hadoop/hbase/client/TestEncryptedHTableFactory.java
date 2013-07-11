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

import static org.junit.Assert.assertTrue;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
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
public class TestEncryptedHTableFactory {
  private static final Log LOG = LogFactory.getLog(TestEncryptedHTableFactory.class);

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
    TEST_UTIL.createTable(TABLE, FAMILY).close();
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    if (inited) {
      TEST_UTIL.shutdownMiniCluster();
    }
  }

  @Test
  public void testFactory() throws Exception {
    if (inited) {
      LOG.warn("testFactory skipped");
      return;
    }
    HTableInterfaceFactory factory = new EncryptedHTableFactory();
    HTableInterface ht = factory.createHTableInterface(TEST_UTIL.getConfiguration(), TABLE);
    try {
      assertTrue(ht instanceof EncryptedHTable);
    } finally {
      ht.close();
    }
  }

  @Test
  public void testTablePoolFactory() throws Exception {
    if (inited) {
      LOG.warn("testTablePoolFactory skipped");
      return;
    }

    final byte[] ROW = Bytes.toBytes("testRow");
    final byte[] QUALIFIER = Bytes.toBytes("qualifier");
    final byte[] VALUE = Bytes.toBytes("testValue");

    // Create test data
    HTableInterface t = new EncryptedHTable(TEST_UTIL.getConfiguration(), TABLE);
    try {
      t.put(new Put(ROW).add(FAMILY, QUALIFIER, VALUE));
    } finally {
      t.close();
    }

    // Test HTablePool with EncryptedHTableFactory
    HTablePool pool = new HTablePool(TEST_UTIL.getConfiguration(), 10,
      new EncryptedHTableFactory());
    try {
      HTableInterface ht = pool.getTable(TABLE);
      try {
        // We will get back an instance of HTablePool.PooledHTable so can't
        // test directly if the EncryptedHTableFactory was used. Instead we
        // have to verify the data is properly decrypted.
        byte[] data = ht.get(new Get(ROW)).getValue(FAMILY, QUALIFIER);
        assertTrue(Bytes.equals(data, VALUE));
      } finally {
        ht.close();
      }
    } finally {
      pool.close();
    }
  }

}
