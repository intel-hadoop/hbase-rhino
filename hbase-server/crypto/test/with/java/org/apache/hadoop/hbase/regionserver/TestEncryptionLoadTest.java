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
package org.apache.hadoop.hbase.regionserver;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.LargeTests;
import org.apache.hadoop.hbase.io.compress.Compression;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.io.encoding.DataBlockEncoding;
import org.apache.hadoop.hbase.util.TestMiniClusterLoadParallel;

import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@Category(LargeTests.class)
@RunWith(Parameterized.class)
public class TestEncryptionLoadTest extends TestMiniClusterLoadParallel {

  @Parameters
  public static Collection<Object[]> parameters() {
    List<Object[]> parameters = new ArrayList<Object[]>();
    // Baselines
    parameters.add(new Object[]{ Encryption.Algorithm.NONE, Compression.Algorithm.NONE,
     DataBlockEncoding.NONE, false });
    //parameters.add(new Object[]{ Encryption.Algorithm.NONE, Compression.Algorithm.SNAPPY,
    // DataBlockEncoding.NONE, false });
    //parameters.add(new Object[]{ Encryption.Algorithm.NONE, Compression.Algorithm.GZ,
    //  DataBlockEncoding.NONE, false });
    // AES
    parameters.add(new Object[]{ Encryption.Algorithm.AES,  Compression.Algorithm.NONE,
      DataBlockEncoding.NONE, true });
    // AES without WAL encryption
    parameters.add(new Object[]{ Encryption.Algorithm.AES,  Compression.Algorithm.NONE,
      DataBlockEncoding.NONE, false });
    // AES+snappy
    //parameters.add(new Object[]{ Encryption.Algorithm.AES,  Compression.Algorithm.SNAPPY,
    //  DataBlockEncoding.NONE, true });
    // AES+snappy without WAL encryption
    //parameters.add(new Object[]{ Encryption.Algorithm.AES,  Compression.Algorithm.SNAPPY,
    //  DataBlockEncoding.NONE, false });
    return parameters;
  }

  private final Compression.Algorithm compressionAlgorithm;
  private final Encryption.Algorithm cryptoAlgorithm;
  private Encryption.Context context;

  public TestEncryptionLoadTest(Encryption.Algorithm crypto, Compression.Algorithm compression,
      DataBlockEncoding encoding, boolean encryptWAL) {
    super(false, encoding);
    this.cryptoAlgorithm = crypto;
    this.compressionAlgorithm = compression;

    // By default the block cache is 25% of heap, lower this to 5% to simulate
    // heap pressure under real world conditions, and resulting increased IO
    conf.setFloat("hfile.block.cache.size", 0.05f);

    if (cryptoAlgorithm != Encryption.Algorithm.NONE) {
      context = Encryption.newContext(conf);
      context.setAlgorithm(cryptoAlgorithm);
      if (Encryption.getEncryptionCodec(context) == null) {
        throw new RuntimeException("Crypto codec " + cryptoAlgorithm.getName() + " not loaded");
      }
      context.setKey("123456");
      // Set up key provider for WAL encryption and encrypted stores
      final String keyProvider = "org.apache.hadoop.io.crypto.KeyProviderForTesting"; 
      final String keyProviderParams = "123456";
      conf.set(HConstants.CRYPTO_KEYPROVIDER_CONF_KEY, keyProvider);
      conf.set(HConstants.CRYPTO_KEYPROVIDER_PARAMETERS_KEY, keyProviderParams);
      Encryption.injectProviderForTesting(keyProvider, keyProviderParams);
      // Enable WAL encryption
      conf.setBoolean(HConstants.ENABLE_WAL_ENCRYPTION, encryptWAL);
    }

    // Disable local HDFS shortcut reads to avoid exceptions every time a new
    // block reader is created
    conf.setBoolean("dfs.client.read.shortcircuit", false);
  }

  @Override
  protected void createPreSplitLoadTestTable(HTableDescriptor htd, HColumnDescriptor hcd)
      throws IOException {
    if (compressionAlgorithm != Compression.Algorithm.NONE) {
      hcd.setCompressionType(compressionAlgorithm);
    }
    if (cryptoAlgorithm != Encryption.Algorithm.NONE) {
      hcd.setEncryptionType(cryptoAlgorithm);
      hcd.setEncryptionKey(conf, context.getKeyBytes());
    }
    super.createPreSplitLoadTestTable(htd, hcd);
  }

  @Override
  protected int numKeys() {
    return 200000;
  }

}
