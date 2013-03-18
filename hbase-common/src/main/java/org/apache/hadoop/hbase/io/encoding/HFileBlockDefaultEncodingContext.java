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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.apache.hadoop.hbase.io.compress.Compression;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.io.hfile.BlockType;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;

import com.google.common.base.Preconditions;

/**
 * A default implementation of {@link HFileBlockEncodingContext}. It will
 * compress the data section as one continuous buffer.
 *
 * @see HFileBlockDefaultDecodingContext for the decompression part
 *
 */
public class HFileBlockDefaultEncodingContext implements
    HFileBlockEncodingContext {

  private byte[] onDiskBytesWithHeader;
  private byte[] uncompressedBytesWithHeader;
  private BlockType blockType;
  private final DataBlockEncoding encodingAlgo;

  /** Compressor, which is also reused between consecutive blocks. */
  private Compressor compressor;

  /** Crypto codec, reused between consecutive blocks. */
  private Compressor encryptor;

  /** Compression output stream */
  private CompressionOutputStream compressionStream;

  /** Underlying stream to write compressed bytes to */
  private ByteArrayOutputStream compressedByteStream;

  /** Compression algorithm for all blocks this instance writes. */
  private final Compression.Algorithm compressionAlgorithm;

  /** Encryption output stream */
  private CompressionOutputStream cryptoStream;

  /** Underlying stream to write encrypted bytes to */
  private ByteArrayOutputStream cryptoByteStream;

  /** Crypto context */
  private final Encryption.Context cryptoContext;

  private ByteArrayOutputStream encodedStream = new ByteArrayOutputStream();
  private DataOutputStream dataOut = new DataOutputStream(encodedStream);

  private final byte[] dummyHeader;

  /**
   * @param compressionAlgorithm compression algorithm used
   * @param encoding encoding used
   * @param headerBytes dummy header bytes
   */
  public HFileBlockDefaultEncodingContext(
      Compression.Algorithm compressionAlgorithm,
      Encryption.Context cryptoContext,
      DataBlockEncoding encoding, byte[] headerBytes) {
    this.encodingAlgo = encoding;
    this.compressionAlgorithm = compressionAlgorithm == null ?
        Compression.Algorithm.NONE : compressionAlgorithm;
    this.cryptoContext = cryptoContext;

    if (this.compressionAlgorithm != Compression.Algorithm.NONE) {
      compressor = compressionAlgorithm.getCompressor();
      compressedByteStream = new ByteArrayOutputStream();
      try {
        compressionStream = compressionAlgorithm.createPlainCompressionStream(compressedByteStream,
          compressor);
      } catch (IOException e) {
        throw new RuntimeException("Could not create compression stream for algorithm " +
          compressionAlgorithm, e);
      }
    }

    if (cryptoContext != null) {
      // encrypt in place of compression
      Encryption.Algorithm cryptoAlgorithm = cryptoContext.getAlgorithm();
      encryptor = cryptoAlgorithm.getEncryptor(cryptoContext);
      cryptoByteStream = new ByteArrayOutputStream();
      try {
        cryptoStream = cryptoAlgorithm.createEncryptionStream(cryptoByteStream,
          encryptor, cryptoContext);
      } catch (IOException e) {
        throw new RuntimeException("Could not create encryption stream for algorithm " +
          cryptoAlgorithm, e);
      }
    }

    dummyHeader = Preconditions.checkNotNull(headerBytes, 
      "Please pass HFileBlock.HFILEBLOCK_DUMMY_HEADER instead of null for param headerBytes");
  }

  /**
   * prepare to start a new encoding.
   * @throws IOException
   */
  public void prepareEncoding() throws IOException {
    encodedStream.reset();
    dataOut.write(dummyHeader);
    if (encodingAlgo != null
        && encodingAlgo != DataBlockEncoding.NONE) {
      encodingAlgo.writeIdInBytes(dataOut);
    }
  }

  @Override
  public void postEncoding(BlockType blockType)
      throws IOException {
    dataOut.flush();
    compressAfterEncoding(encodedStream.toByteArray(), blockType);
    this.blockType = blockType;
  }

  /**
   * @param uncompressedBytesWithHeader
   * @param blockType
   * @throws IOException
   */
  public void compressAfterEncoding(byte[] uncompressedBytesWithHeader,
      BlockType blockType) throws IOException {
    compressAfterEncoding(uncompressedBytesWithHeader, blockType, dummyHeader);
  }

  /**
   * @param uncompressedBytesWithHeader
   * @param blockType
   * @param headerBytes
   * @throws IOException
   */
  protected void compressAfterEncoding(byte[] uncompressedBytesWithHeader,
      BlockType blockType, byte[] headerBytes) throws IOException {
    this.uncompressedBytesWithHeader = uncompressedBytesWithHeader;

    // TODO: Consider using buffers instead of byte streams

    // +--------------------------+
    // | 4 bytes plaintext length |
    // +--------------------------+
    // | encrypted block data ... |
    // +--------------------------+

    if (cryptoContext != null) {
      cryptoByteStream.reset();
      cryptoByteStream.write(headerBytes);
      cryptoStream.resetState();
      if (compressionAlgorithm != Compression.Algorithm.NONE) {
        compressedByteStream.reset();
        // compress excluding header, then encrypt
        compressionStream.resetState();
        compressionStream.write(uncompressedBytesWithHeader,
          headerBytes.length,
          uncompressedBytesWithHeader.length - headerBytes.length);
        compressionStream.flush();
        compressionStream.finish();
        byte[] compressedBytes = compressedByteStream.toByteArray();
        int payloadLen = compressedBytes.length;
        cryptoByteStream.write(Bytes.toBytes(payloadLen));
        cryptoStream.write(compressedBytes);
      } else {
        int payloadLen = uncompressedBytesWithHeader.length - headerBytes.length;
        cryptoByteStream.write(Bytes.toBytes(payloadLen));
        cryptoStream.write(uncompressedBytesWithHeader, headerBytes.length,
          payloadLen);
      }
      cryptoStream.flush();
      cryptoStream.finish();
      onDiskBytesWithHeader = cryptoByteStream.toByteArray();
    } else {
      if (compressionAlgorithm != Compression.Algorithm.NONE) {
        compressedByteStream.reset();
        compressedByteStream.write(headerBytes);
        compressionStream.resetState();
        // compress excluding header
        compressionStream.write(uncompressedBytesWithHeader,
          headerBytes.length,
          uncompressedBytesWithHeader.length - headerBytes.length);
        compressionStream.flush();
        compressionStream.finish();
        onDiskBytesWithHeader = compressedByteStream.toByteArray();
      } else {
        onDiskBytesWithHeader = uncompressedBytesWithHeader;
      }
    }

    this.blockType = blockType;
  }

  @Override
  public byte[] getOnDiskBytesWithHeader() {
    return onDiskBytesWithHeader;
  }

  @Override
  public byte[] getUncompressedBytesWithHeader() {
    return uncompressedBytesWithHeader;
  }

  @Override
  public BlockType getBlockType() {
    return blockType;
  }

  /**
   * Releases the compressor this writer uses to compress blocks into the
   * compressor pool.
   */
  @Override
  public void close() {
    if (compressor != null) {
      compressionAlgorithm.returnCompressor(compressor);
      compressor = null;
    }
    if (encryptor != null) {
      cryptoContext.getAlgorithm().returnEncryptor(encryptor);
      encryptor = null;
    }
  }

  @Override
  public Compression.Algorithm getCompression() {
    return this.compressionAlgorithm;
  }

  @Override
  public Encryption.Context getCryptoContext() {
    return this.cryptoContext;
  }

  public DataOutputStream getOutputStreamForEncoder() {
    return this.dataOut;
  }

  @Override
  public DataBlockEncoding getDataBlockEncoding() {
    return this.encodingAlgo;
  }

  @Override
  public int getHeaderSize() {
    return this.dummyHeader.length;
  }

}
