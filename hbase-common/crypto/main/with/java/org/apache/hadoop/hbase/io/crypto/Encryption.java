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

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.util.Pair;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.compress.CodecPool;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.compress.DoNotPool;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Decryptor;
import org.apache.hadoop.io.crypto.Encryptor;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.KeyProvider;
import org.apache.hadoop.util.ReflectionUtils;
import org.apache.hadoop.util.StringUtils;

import com.google.common.annotations.VisibleForTesting;

/**
 * A facade for encryption codec support.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public abstract class Encryption {
  private static final Log LOG = LogFactory.getLog(Encryption.class);

  public static Context newContext() {
    return new Context(HBaseConfiguration.create());
  }

  public static Context newContext(Configuration conf) {
    return new Context(new Configuration(conf));
  }

  public static class Context implements Configurable {

    protected Algorithm algorithm = Algorithm.NONE;
    protected byte[] keyBytes;
    protected String keyBytesHash;
    protected Configuration conf;
    protected CryptoContext delegate;

    protected Context(Configuration conf) {
      this.conf = conf;
      this.conf.setBoolean("hadoop.native.lib", true);
      this.delegate = new CryptoContext();
    }

    @Override
    public String toString() {
      return "encryption: context [algorithm=" + algorithm.getName() +
        "] keyHash=[" + keyBytesHash.substring(0, 8) + "...]";
    }

    public Algorithm getAlgorithm() {
      return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
      this.algorithm = algorithm;
    }

    @Override
    public Configuration getConf() {
      return conf;
    }

    @Override
    public void setConf(Configuration conf) {
      this.conf = conf;
    }

    public CryptoContext getDelegate() {
      return delegate;
    }

    public byte[] getKeyBytes() {
      return keyBytes;
    }

    public String getKeyBytesHash() {
      return keyBytesHash;
    }

    public void setKey(String string) {
      try {
        Key key = Key.derive(string);
        delegate.setKey(key);
        keyBytes = key.getRawKey();
        keyBytesHash = StringUtils.byteToHexString(hash256(keyBytes));
      } catch (CryptoException e) {
        throw new RuntimeException(e);
      }
    }

    public void setKey(String algorithm, String format, byte[] rawKey) {
      Key key = new Key();
      key.setCryptographicAlgorithm(algorithm);
      key.setCryptographicLength(rawKey.length * Bytes.SIZEOF_BYTE);
      key.setFormat(format);
      key.setRawKey(rawKey);
      delegate.setKey(key);
      keyBytes = rawKey;
      keyBytesHash = StringUtils.byteToHexString(hash256(keyBytes));
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
   * Returns the classloader to load the Codec class from.
   * @return
   */
  private static ClassLoader getClassLoaderForCodec() {
    ClassLoader cl = Thread.currentThread().getContextClassLoader();
    if (cl == null) {
      cl = Encryption.class.getClassLoader();
    }
    if (cl == null) {
      cl = ClassLoader.getSystemClassLoader();
    }
    if (cl == null) {
      throw new RuntimeException("A ClassLoader to load the Codec could not be determined");
    }
    return cl;
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
      private transient CompressionCodec codec;

      @Override
      public CompressionCodec getCodec(Configuration conf) {
        if (codec == null) {
          try {
            Class<?> externalCodec = getClassLoaderForCodec()
              .loadClass("org.apache.hadoop.io.crypto.aes.SimpleAESCodec");
            // Set the crypto block size to a reasonable value for HFile
            conf.setInt("hadoop.io.crypto.simpleaes.block.size", 64 * 1024);
            codec = (CompressionCodec) ReflectionUtils.newInstance(externalCodec,
              conf);
          } catch (ClassNotFoundException e) {
            LOG.warn(e);
            return null;
          }
        }
        return codec;
      }
    };

    private final String codecName;

    Algorithm(String name) {
      this.codecName = name;
    }

    abstract CompressionCodec getCodec(Configuration conf);

    public InputStream createDecryptionStream(InputStream downStream,
        Decompressor decryptor, Context context) throws IOException {
      CompressionCodec codec = getEncryptionCodec(context);
      ((Decryptor)decryptor).setCryptoContext(context.getDelegate());
      return codec.createInputStream(downStream, decryptor);
    }

    /**
     * Creates an encryption stream without any additional wrapping into
     * buffering streams.
     */
    public CompressionOutputStream createEncryptionStream(OutputStream downStream,
        Compressor encryptor, Context context) throws IOException {
      CompressionCodec codec = getEncryptionCodec(context);
      ((Encryptor)encryptor).setCryptoContext(context.getDelegate());
      return codec.createOutputStream(downStream, encryptor);
    }

    public Compressor getEncryptor(Context context) {
      CompressionCodec codec = getCodec(context.getConf());
      if (codec != null) {
        Compressor compressor = CodecPool.getCompressor(codec);
        if (compressor != null) {
          if (compressor.finished()) {
            LOG.warn("Encryptor obtained from CodecPool is already finished()");
          }
          compressor.reset();
        }
        return compressor;
      }
      return null;
    }

    public void returnEncryptor(Compressor compressor) {
      if (compressor != null) {
        CodecPool.returnCompressor(compressor);
      }
    }

    public Decompressor getDecryptor(Context context) {
      CompressionCodec codec = getCodec(context.getConf());
      if (codec != null) {
        Decompressor decompressor = CodecPool.getDecompressor(codec);
        if (decompressor != null) {
          if (decompressor.finished()) {
            LOG.warn("Decompressor obtained from CodecPool is already finished()");
          }
          decompressor.reset();
        }
        return decompressor;
      }

      return null;
    }

    public void returnDecryptor(Decompressor decompressor) {
      if (decompressor != null) {
        CodecPool.returnDecompressor(decompressor);
        if (decompressor.getClass().isAnnotationPresent(DoNotPool.class)) {
          decompressor.end();
        }
      }
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
    CompressionCodec codec = null;
    codec = context.getAlgorithm().getCodec(context.getConf());
    ((CryptoCodec)codec).setCryptoContext(context.getDelegate());
    return codec;
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
    CompressionCodec codec = getEncryptionCodec(context);
    CompressionOutputStream cout = codec.createOutputStream(out);
    try {
      cout.write(src, srcOffset, srcLength);
    } finally {
      cout.close();
    }
  }

  private static void copyBytes(OutputStream out, InputStream in, long count)
      throws IOException {
    byte buf[] = new byte[4096];
    long remaining = count;
    while (remaining > 0) {
      int toRead = (int)(remaining < buf.length ? remaining : buf.length);
      int read = in.read(buf, 0, toRead);
      if (read < 0) {
        break;
      }
      out.write(buf, 0, read);
      remaining -= read;
    }
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
    CompressionCodec codec = getEncryptionCodec(context);
    CompressionOutputStream cout = codec.createOutputStream(out);
    try {
      IOUtils.copyBytes(in, cout, 4096);
    } finally {
      cout.close();
    }
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
    byte[] buffer = new byte[srcLength];
    in.readFully(buffer);
    decrypt(dest, destOffset, new ByteArrayInputStream(buffer), destSize, context);
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
    CompressionCodec codec = getEncryptionCodec(context);
    CompressionInputStream cin = codec.createInputStream(in);
    try {
      IOUtils.readFully(cin, dest, destOffset, destSize);
    } finally {
      cin.close();
    }
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
    CompressionCodec codec = getEncryptionCodec(context);
    CompressionInputStream cin = codec.createInputStream(in);
    try {
      copyBytes(out, cin, outLen);
    } finally {
      cin.close();
    }
  }

  /*
   * Cache key providers to avoid expensive (re)initialization for each query.
   */

  private static final Map<Pair<String,String>, KeyProvider> providerCache =
    new HashMap<Pair<String,String>, KeyProvider>();
  private static KeyProvider providerForTesting;

  private static KeyProvider getKeyProvider(Configuration conf) {
    if (providerForTesting != null) {
      return providerForTesting;
    }
    synchronized (providerCache) {
      String providerClassName = conf.get(HConstants.CRYPTO_KEYPROVIDER_CONF_KEY,
        "org.apache.hadoop.io.crypto.KeyStoreKeyProvider");
      String providerParameters = conf.get(HConstants.CRYPTO_KEYPROVIDER_PARAMETERS_KEY, "");
      Pair<String,String> providerCacheKey = new Pair<String,String>(providerClassName,
        providerParameters);
      KeyProvider provider = providerCache.get(providerCacheKey);
      if (provider == null) try {
        provider = (KeyProvider)ReflectionUtils.newInstance(getClassLoaderForCodec()
            .loadClass(providerClassName),
          conf);
        provider.init(providerParameters);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      providerCache.put(providerCacheKey, provider);
      return provider;
    }
  }

  @VisibleForTesting
  public static void injectProviderForTesting() {
    try {
      injectProviderForTesting("org.apache.hadoop.io.crypto.KeyProviderForTesting",
        "123456");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @VisibleForTesting
  public static void injectProviderForTesting(String providerClass, String providerParameters) {
    try {
      KeyProvider provider = (KeyProvider)Class.forName(providerClass).newInstance();
      provider.init(providerParameters);
      providerForTesting = provider;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
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
    KeyProvider provider = (KeyProvider)getKeyProvider(conf);
    if (provider != null) try {
      Key[] keys = provider.getKeys(new String[] { subject });
      if (keys != null && keys.length > 0) {
        return (byte[]) keys[0].getRawKey();
      }
    } catch (Exception e) {
      throw new IOException(e);
    }
    throw new IOException("No key found for subject '" + subject + "'");
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
    Context context = newContext();
    byte[] key = getSecretKeyForSubject(subject, conf);
    if (key == null) {
      throw new IOException("No key found for subject '" + subject + "'");
    }
    context.setAlgorithm(algorithm);
    context.setKey(algorithm, key);
    encrypt(out, in, context);
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
    Context context = newContext();
    byte[] key = getSecretKeyForSubject(subject, conf);
    if (key == null) {
      throw new IOException("No key found for subject '" + subject + "'");
    }
    context.setAlgorithm(algorithm);
    context.setKey(algorithm, key);
    decrypt(out, in, outLen, context);
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
