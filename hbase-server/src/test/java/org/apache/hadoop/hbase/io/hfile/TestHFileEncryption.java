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
package org.apache.hadoop.hbase.io.hfile;

import static org.junit.Assert.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.HBaseTestingUtility;
import org.apache.hadoop.hbase.SmallTests;
import org.apache.hadoop.hbase.io.compress.Compression;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.util.Bytes;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(SmallTests.class)
public class TestHFileEncryption {
  private static final Log LOG = LogFactory.getLog(TestHFileEncryption.class);
  private static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  private static final Configuration conf = TEST_UTIL.getConfiguration();
  private static FileSystem fs;

  @BeforeClass
  public static void setUp() throws Exception {
    fs = FileSystem.get(conf);
    Encryption.injectProviderForTesting();
  }

  @Test
  public void testEncryptionOrdinance() throws Exception {
    assertTrue(Encryption.Algorithm.NONE.ordinal() == 0);
    assertTrue(Encryption.Algorithm.AES.ordinal() == 1);
  }

  private int writeBlock(FSDataOutputStream os, Compression.Algorithm algo,
      Encryption.Context context, int size) throws IOException {
    HFileBlock.Writer hbw = new HFileBlock.Writer(algo, context, null, true,
      HFile.DEFAULT_CHECKSUM_TYPE, HFile.DEFAULT_BYTES_PER_CHECKSUM);
    DataOutputStream dos = hbw.startWriting(BlockType.DATA);
    for (int j = 0; j < size; j++) {
      dos.writeInt(j);
    }
    hbw.writeHeaderAndData(os);
    return hbw.getOnDiskSizeWithHeader();
  }

  private long readAndVerifyBlock(long pos, HFileBlock.FSReaderV2 hbr, int size)
      throws IOException {
    HFileBlock b = hbr.readBlockData(pos, -1, -1, false);
    assertEquals(0, HFile.getChecksumFailuresCount());
    b.sanityCheck();
    DataInputStream dis = b.getByteStream();
    for (int i = 0; i < size; i++) {
      int read = dis.readInt();
      if (read != i) {
        fail("Block data corrupt at element " + i);
      }
    }
    return b.getOnDiskSizeWithHeader();
  }

  @Test
  public void testDataBlockEncryption() throws IOException {
    Encryption.Context context = Encryption.newContext(conf);
    context.setAlgorithm(Encryption.Algorithm.AES);
    context.setKey("123456");
    if (Encryption.getEncryptionCodec(context) == null) {
      LOG.info("testDataBlockEncryption skipped because codec is not loaded");
      return;
    }
    final int blockSize = 1000;
    final int blocks = 5;
    for (Compression.Algorithm algo : TestHFileBlock.COMPRESSION_ALGORITHMS) {
      Path path = new Path(TEST_UTIL.getDataTestDir(), "block_v2_" + algo + "_AES");
      LOG.info("testDataBlockEncryption: encryption=AES compression=" + algo);
      long totalSize = 0;
      FSDataOutputStream os = fs.create(path);
      try {
        for (int i = 0; i < blocks; i++) { 
          totalSize += writeBlock(os, algo, context, blockSize);
        }
      } finally {
        os.close();
      }
      FSDataInputStream is = fs.open(path);
      try {
        HFileBlock.FSReaderV2 hbr = new HFileBlock.FSReaderV2(is, algo, context, totalSize);
        hbr.setIncludesMemstoreTS(true);
        long pos = 0;
        for (int i = 0; i < blocks; i++) {
          pos += readAndVerifyBlock(pos, hbr, blockSize);
        }
      } finally {
        is.close();
      }
    }
  }

  @Test
  public void testLargeDataBlockEncryption() throws IOException {
    Encryption.Context context = Encryption.newContext(conf);
    context.setAlgorithm(Encryption.Algorithm.AES);
    context.setKey("123456");
    if (Encryption.getEncryptionCodec(context) == null) {
      LOG.info("testLargeDataBlockEncryption skipped because codec is not loaded");
      return;
    }
    final int blockSize = 32768; // 128k
    Path path = new Path(TEST_UTIL.getDataTestDir(), "block_v2_NONE_AES_large");
    long totalSize = 0;
    FSDataOutputStream os = fs.create(path);
    try {
      totalSize += writeBlock(os, Compression.Algorithm.NONE, context, blockSize);
    } finally {
      os.close();
    }
    FSDataInputStream is = fs.open(path);
    try {
      HFileBlock.FSReaderV2 hbr = new HFileBlock.FSReaderV2(is, Compression.Algorithm.NONE,
        context, totalSize);
      hbr.setIncludesMemstoreTS(true);
      readAndVerifyBlock(0, hbr, blockSize);
    } finally {
      is.close();
    }
  }

  @Test
  public void testHFileEncryptionMetadata() throws Exception {
    Encryption.Context writerContext = Encryption.newContext(conf);
    writerContext.setAlgorithm(Encryption.Algorithm.AES);
    writerContext.setKey("123456");
    if (Encryption.getEncryptionCodec(writerContext) == null) {
      LOG.info("testHFileEncryptionMetadata skipped because codec is not loaded");
      return;
    }
    CacheConfig cacheConf = new CacheConfig(conf);
    // write a simple encrypted hfile
    Path path = new Path(TEST_UTIL.getDataTestDir(), "cryptometa.hfile");
    FSDataOutputStream out = fs.create(path);
    HFile.Writer writer = HFile.getWriterFactory(conf, cacheConf)
      .withOutputStream(out)
      .withEncryptionContext(writerContext)
      .create();
    writer.append("foo".getBytes(), "value".getBytes());
    writer.close();
    out.close();
    // read it back in and validate correct crypto metadata
    HFile.Reader reader = HFile.createReader(fs, path, cacheConf);
    reader.loadFileInfo();
    FixedFileTrailer trailer = reader.getTrailer();
    assertTrue(trailer.getEncryptionKeyBlockOffset() != 0L);
    Encryption.Context readerContext = reader.getCryptoContext();
    assertEquals(readerContext.getAlgorithm(), writerContext.getAlgorithm());
    assertTrue(Bytes.equals(readerContext.getKeyBytes(),
      writerContext.getKeyBytes()));
  }

}
