/**
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
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.hbase.io.crypto;

import java.io.DataInput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;

import com.google.common.annotations.VisibleForTesting;

/**
 * A facade for encryption codec support.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public abstract class Encryption {

  public static Context newContext() {
    return new Context(HBaseConfiguration.create());
  }

  public static Context newContext(Configuration conf) {
    return new Context(new Configuration(conf));
  }

  public static class Context implements Configurable {

    protected Configuration conf;

    protected Context(Configuration conf) {
      this.conf = conf;
    }

    @Override
    public String toString() {
      throw new UnsupportedOperationException();
    }

    public Algorithm getAlgorithm() {
      throw new UnsupportedOperationException();
    }

    public void setAlgorithm(Algorithm algorithm) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Configuration getConf() {
      return conf;
    }

    @Override
    public void setConf(Configuration conf) {
      this.conf = conf;
    }

    public byte[] getKeyBytes() {
      throw new UnsupportedOperationException();
    }

    public String getKeyBytesHash() {
      throw new UnsupportedOperationException();
    }

    public void setKey(String string) {
      throw new UnsupportedOperationException();
    }

    public void setKey(String algorithm, String format, byte[] rawKey) {
      throw new UnsupportedOperationException();
    }

    public void setKey(String algorithm, byte[] rawKey) {
      setKey(algorithm, null, rawKey);
    }

    public void setKey(Algorithm algorithm, String format, byte[] rawKey) {
      setKey(algorithm.getName(), format, rawKey);
    }

    public void setKey(Algorithm algorithm, byte[] rawKey) {
      setKey(algorithm.getName(), null, rawKey);
    }
  }

  /**
   * Prevent the instantiation of class.
   */
  private Encryption() {
    super();
  }

  /**
   * Encryption algorithms. The ordinal of these cannot change or else you
   * risk breaking all existing HFiles out there.  Even the ones that are
   * not encrypted! (They use the NONE algorithm)
   */
  public static enum Algorithm {
    NONE("none") {
      @Override
      CompressionCodec getCodec(Configuration conf) {
        return null;
      }
    },
    AES("aes") {
      @Override
      CompressionCodec getCodec(Configuration conf) {
        throw new UnsupportedOperationException();
      }
    };

    private final String codecName;

    Algorithm(String name) {
      this.codecName = name;
    }

    abstract CompressionCodec getCodec(Configuration conf);

    public InputStream createDecryptionStream(InputStream downStream,
        Decompressor decryptor, Context context) throws IOException {
      throw new UnsupportedOperationException();
    }

    /**
     * Creates an encryption stream without any additional wrapping into
     * buffering streams.
     */
    public CompressionOutputStream createEncryptionStream(OutputStream downStream,
        Compressor encryptor, Context context) throws IOException {
      throw new UnsupportedOperationException();
    }

    public Compressor getEncryptor(Context context) {
      throw new UnsupportedOperationException();
    }

    public void returnEncryptor(Compressor compressor) {
      throw new UnsupportedOperationException();
    }

    public Decompressor getDecryptor(Context context) {
      throw new UnsupportedOperationException();
    }

    public void returnDecryptor(Decompressor decompressor) {
      throw new UnsupportedOperationException();
    }

    public String getName() {
      return codecName;
    }
  }

  public static Algorithm getEncryptionAlgorithmByName(String name) {
    Algorithm[] algos = Algorithm.class.getEnumConstants();
    for (Algorithm a : algos) {
      if (a.getName().equalsIgnoreCase(name)) {
        return a;
      }
    }

    throw new IllegalArgumentException("Unsupported encryption algorithm name: " + name);
  }

  /**
   * Get names of supported compression algorithms.
   *
   * @return Array of strings, each represents a supported compression
   * algorithm. Currently, the following compression algorithms are supported.
   */
  public static String[] getSupportedAlgorithms() {
    Algorithm[] algos = Algorithm.class.getEnumConstants();

    String[] ret = new String[algos.length];
    int i = 0;
    for (Algorithm a : algos) {
      ret[i++] = a.getName();
    }

    return ret;
  }

  /**
   * @return the crypto codec for the given algorithm
   */
  public static CompressionCodec getEncryptionCodec(Context context) {
    throw new UnsupportedOperationException();
  }

  /**
   * Encrypts a block of ciphertext with the given algorithm and context
   * @param out
   * @param src
   * @param srcOffset
   * @param srcLength
   * @param context
   * @throws IOException
   */
  public static void encrypt(OutputStream out, byte[] src, int srcOffset,
      int srcLength, Context context) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Encrypts a block of ciphertext with the given algorithm and context
   * @param out
   * @param in
   * @param context
   * @throws IOException
   */
  public static void encrypt(OutputStream out, InputStream in, Context context)
      throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Decrypts a block of ciphertext with the given algorithm and context
   * @param dest
   * @param destOffset
   * @param in
   * @param destLength
   * @param context
   * @throws IOException
   */
  public static void decrypt(byte[] dest, int destOffset, DataInput in,
      int srcLength, int destSize, Context context) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Decrypts a block of ciphertext read in from a stream with the given
   * algorithm and context
   * @param dest
   * @param destOffset
   * @param in
   * @param destSize
   * @param context
   * @throws IOException
   */
  public static void decrypt(byte[] dest, int destOffset, InputStream in,
      int destSize, Context context) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Decrypts a block of ciphertext read in from a stream with the given
   * algorithm and context
   * @param out
   * @param in
   * @param outLen
   * @param context
   * @throws IOException
   */
  public static void decrypt(OutputStream out, InputStream in, int outLen,
      Context context) throws IOException {
    throw new UnsupportedOperationException();
  }

  @VisibleForTesting
  public static void injectProviderForTesting() {
    throw new UnsupportedOperationException();
  }

  @VisibleForTesting
  public static void injectProviderForTesting(String providerClass, String providerParameters) {
    throw new UnsupportedOperationException();
  }

  /**
   * Resolves a key for the given subject
   * @param subject
   * @param conf
   * @return a key for the given subject
   * @throws IOException if the key is not found
   */
  public static byte[] getSecretKeyForSubject(String subject, Configuration conf)
      throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Encrypts a block of ciphertext with the symmetric key resolved for the given subject
   * @param out
   * @param in
   * @param subject
   * @param conf
   * @param algorithm
   * @throws IOException
   */
  public static void encryptWithSubjectKey(OutputStream out, InputStream in,
      String subject, Configuration conf, Algorithm algorithm) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Decrypts a block of ciphertext with the symmetric key resolved for the given subject
   * @param out
   * @param in
   * @param outLen
   * @param subject
   * @param conf
   * @param algorithm
   * @throws IOException
   */
  public static void decryptWithSubjectKey(OutputStream out, InputStream in,
      int outLen, String subject, Configuration conf, Algorithm algorithm) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Return the MD5 digest of the concatenation of the supplied arguments.
   */
  public static byte[] hash128(byte[]... args) {
    byte[] result = new byte[16];
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      for (byte[] arg: args) {
        md.update(arg);
      }
      md.digest(result, 0, result.length);
      return result;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (DigestException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Return the SHA-256 digest of the concatenation of the supplied arguments.
   */
  public static byte[] hash256(byte[]... args) {
    byte[] result = new byte[32];
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      for (byte[] arg: args) {
        md.update(arg);
      }
      md.digest(result, 0, result.length);
      return result;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (DigestException e) {
      throw new RuntimeException(e);
    }
  }
}
