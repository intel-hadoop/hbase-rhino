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
package org.apache.hadoop.hbase.io.encoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.hadoop.hbase.io.compress.Compression;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.io.IOUtils;

/**
 * A default implementation of {@link HFileBlockDecodingContext}. It assumes the
 * block data section is compressed as a whole.
 *
 * @see HFileBlockDefaultEncodingContext for the default compression context
 *
 */
public class HFileBlockDefaultDecodingContext implements
    HFileBlockDecodingContext {

  private final Compression.Algorithm compressAlgo;
  private final Encryption.Context cryptoContext;

  public HFileBlockDefaultDecodingContext(Compression.Algorithm compressAlgo,
      Encryption.Context cryptoContext) {
    this.compressAlgo = compressAlgo;
    this.cryptoContext = cryptoContext;
  }

  @Override
  public void prepareDecoding(int onDiskSizeWithoutHeader, int uncompressedSizeWithoutHeader,
      ByteBuffer blockBufferWithoutHeader, byte[] onDiskBlock, int offset) throws IOException {
    ByteArrayInputStream in = new ByteArrayInputStream(onDiskBlock, offset, onDiskSizeWithoutHeader);
    if (cryptoContext != null) {

      // TODO: Consider using buffers instead of byte streams to avoid some
      // possibly unnecessary allocations

      // +--------------------------+
      // | 4 bytes plaintext length |
      // +--------------------------+
      // | encrypted block data ... |
      // +--------------------------+

      byte[] plaintextLengthBytes = new byte[Bytes.SIZEOF_INT];
      in.read(plaintextLengthBytes);
      onDiskSizeWithoutHeader -= Bytes.SIZEOF_INT;
      int plainTextLength = Bytes.toInt(plaintextLengthBytes);
      byte[] plaintextBytes = new byte[onDiskSizeWithoutHeader];
      Encryption.decrypt(plaintextBytes, 0, in, plainTextLength, cryptoContext);
      in = new ByteArrayInputStream(plaintextBytes, 0, plainTextLength);
      onDiskSizeWithoutHeader = plainTextLength;
    }
    if (compressAlgo != Compression.Algorithm.NONE) {
      Compression.decompress(blockBufferWithoutHeader.array(),
        blockBufferWithoutHeader.arrayOffset(), in, onDiskSizeWithoutHeader,
        uncompressedSizeWithoutHeader, compressAlgo);
    } else {
      IOUtils.readFully(in, blockBufferWithoutHeader.array(),
        blockBufferWithoutHeader.arrayOffset(), onDiskSizeWithoutHeader);
    }
  }

  @Override
  public Compression.Algorithm getCompression() {
    return compressAlgo;
  }

  @Override
  public Encryption.Context getCryptoContext() {
    return cryptoContext;
  }
}
