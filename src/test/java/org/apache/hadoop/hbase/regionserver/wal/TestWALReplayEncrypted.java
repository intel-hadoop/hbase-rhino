/**
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
package org.apache.hadoop.hbase.regionserver.wal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.MediumTests;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.junit.BeforeClass;
import org.junit.experimental.categories.Category;

@Category(MediumTests.class)
public class TestWALReplayEncrypted extends TestWALReplay {
  private static final Log LOG = LogFactory.getLog(TestWALReplayEncrypted.class);

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    TestWALReplay.setUpBeforeClass();

    // Check if we can load the encryption codec
    Encryption.Context context = Encryption.newContext();
    context.setAlgorithm(Encryption.Algorithm.AES);
    if (!Encryption.isEncryptionCodecAvailable(context)) {
      LOG.warn("Crypto codec cannot be loaded");
      return;
    }

    Configuration conf = TestWALReplay.TEST_UTIL.getConfiguration();
    conf.setBoolean(HConstants.ENABLE_WAL_ENCRYPTION, true);
    conf.set(HConstants.CRYPTO_KEYPROVIDER_CONF_KEY,
      "org.apache.hadoop.io.crypto.KeyProviderForTesting");
    conf.set(HConstants.CRYPTO_KEYPROVIDER_PARAMETERS_KEY, "123456");
  }

}
