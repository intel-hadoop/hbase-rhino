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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.io.crypto.Encryption;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.util.Bytes;

/**
 * An HTable instance that provides "transparent" client side encryption. The
 * encryption is transparent, but because it happens client side there are
 * limitations: For any family configured for encryption (by default - all),
 * checkAndPut, checkAndDelete, Append, Increment, incrementColumnValue, and
 * filters that operate on value data in a server side context will not work.
 * This is because the server side context does not have key material for
 * decrypting the data there.
 */
public class EncryptedHTable extends HTable {
  private static final Log LOG = LogFactory.getLog(EncryptedHTable.class);

  private Encryption.Context cryptoContext = null;
  private Set<byte[]> familySet = new TreeSet<byte[]>(Bytes.BYTES_COMPARATOR);
  
  public EncryptedHTable(Configuration conf, byte[] tableName) throws IOException {
    super(conf, tableName);
  }

  public EncryptedHTable(Configuration conf, String tableName) throws IOException {
    super(conf, tableName);
  }

  public EncryptedHTable(Configuration conf, byte[] tableName, ExecutorService pool)
      throws IOException {
    super(conf, tableName, pool);
  }

  public EncryptedHTable(byte[] tableName, HConnection connection, ExecutorService pool)
      throws IOException {
    super(tableName, connection, pool);
  }

  protected void checkCryptoContext() throws IOException {
    if (cryptoContext == null) {
      initializeCryptoContext();
    }
  }

  protected void initializeCryptoContext() throws IOException {
    Configuration conf = getConfiguration();
    // Get the { user, table } -> key mapping and make the substitutions
    String mapping = conf.get(HConstants.CRYPTO_USERKEY_NAME_MAPPING_CONF_KEY,
      HConstants.CRYPTO_USERKEY_DEFAULT_NAME_MAPPING);
    String subject = mapping.replace("%t", Bytes.toStringBinary(getTableName()))
      .replace("%u", User.getCurrent().getShortName());
    if (LOG.isDebugEnabled()) {
      LOG.debug("Resolving key for subject '" + subject + "' (mapping='" + mapping +
        "', table='" + Bytes.toStringBinary(getTableName()) + "', user='" +
        User.getCurrent().getShortName() + "')");
    }
    // Create the crypto context
    cryptoContext = Encryption.newContext(conf);
    cryptoContext.setAlgorithm(Encryption.Algorithm.AES);
    // This will throw an IOException if the secret key for the subject cannot
    // be found
    cryptoContext.setKey(Encryption.Algorithm.AES,
      Encryption.getSecretKeyForSubject(subject, conf));
    if (LOG.isDebugEnabled()) {
      LOG.debug("Successfully resolved key for subject '" + subject + "'");
    }
  }

  protected boolean inFamilySet(byte[] family) {
    return (familySet.isEmpty() || familySet.contains(family));
  }

  protected boolean inFamilySet(Append append) {
    if (!familySet.isEmpty()) {
      for (byte[] family: append.getFamilyMap().keySet()) {
        if (familySet.contains(family)) {
          return true;
        }
      }
    } else {
      return true;
    }
    return false;
  }

  protected boolean inFamilySet(Increment increment) {
    if (!familySet.isEmpty()) {
      for (byte[] family: increment.getFamilyMap().keySet()) {
        if (familySet.contains(family)) {
          return true;
        }
      }
    } else {
      return true;
    }
    return false;
  }

  /*
   * Encrypted value format:
   * +--------------------------+
   * | 4 bytes plaintext length |
   * +--------------------------+
   * | encrypted data ...       |
   * +--------------------------+
   */

  protected byte[] decrypt(byte[] value) throws IOException {
    if (value.length < Bytes.SIZEOF_INT) {
      throw new IOException("Short value");
    }
    int plaintextLength = Bytes.toInt(value, 0, Bytes.SIZEOF_INT);
    if (plaintextLength > 0) {
      ByteArrayInputStream in = new ByteArrayInputStream(value, Bytes.SIZEOF_INT,
        value.length - Bytes.SIZEOF_INT);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      Encryption.decrypt(out, in, plaintextLength, cryptoContext);
      return out.toByteArray();
    } else {
      return HConstants.EMPTY_BYTE_ARRAY;
    }
  }

  protected KeyValue decrypt(KeyValue kv) throws IOException {
    // Avoid invoking kv.getFamily if we can
    if (!familySet.isEmpty() && !familySet.contains(kv.getFamily())) {
      return kv;
    }
    // TODO: See about modifying the value in place via a ByteBuffer, but for
    // now correctness first
    byte[] value = decrypt(kv.getValue());
    return new KeyValue(kv.getBuffer(), kv.getRowOffset(), kv.getRowLength(),
      kv.getBuffer(), kv.getFamilyOffset(), kv.getFamilyLength(),
      kv.getBuffer(), kv.getQualifierOffset(), kv.getQualifierLength(),
      kv.getTimestamp(), KeyValue.Type.codeToType(kv.getType()),
      value, 0, value.length);
  }

  protected Result decrypt(Result result) throws IOException {
    KeyValue kvs[] = result.raw();
    if (kvs == null) {
      return result;
    }
    for (int i = 0; i < kvs.length; i++) {
      kvs[i] = decrypt(kvs[i]);
    }
    return new Result(kvs);
  }

  private static final byte[] DUMMY_HEADER = Bytes.toBytes((int)0);

  protected byte[] encrypt(byte[] value) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Reserve header space
    out.write(DUMMY_HEADER);
    Encryption.encrypt(out, value, 0, value.length, cryptoContext);
    byte[] transformedValue = out.toByteArray();
    Bytes.putInt(transformedValue, 0, value.length);
    return transformedValue;
  }

  protected KeyValue encrypt(KeyValue kv) throws IOException {
    // Avoid invoking kv.getFamily if we can
    if (!familySet.isEmpty() && !familySet.contains(kv.getFamily())) {
      return kv;
    }
    // It is unlikely we will be able to modify the value in place via a
    // ByteBuffer, because the encryption algorithm may pad the value and
    // write out additional state (e.g. IV)
    byte[] value = encrypt(kv.getValue());
    return new KeyValue(kv.getBuffer(), kv.getRowOffset(), kv.getRowLength(),
      kv.getBuffer(), kv.getFamilyOffset(), kv.getFamilyLength(),
      kv.getBuffer(), kv.getQualifierOffset(), kv.getQualifierLength(),
      kv.getTimestamp(), KeyValue.Type.codeToType(kv.getType()),
      value, 0, value.length);
  }

  protected Put encrypt(Put put) throws IOException {
    Put transformedPut = new Put(put.getRow());
    for (Map.Entry<byte[], List<KeyValue>> entry: put.getFamilyMap().entrySet()) {
      for (KeyValue kv: entry.getValue()) {
        transformedPut.add(encrypt(kv));
      }
    }
    return transformedPut;
  }

  protected class EncryptedResultIterator implements Iterator<Result> {

    private Iterator<Result> delegate;
    
    public EncryptedResultIterator(Iterator<Result> delegate) {
      this.delegate = delegate;
    }

    @Override
    public boolean hasNext() {
      return delegate.hasNext();
    }

    @Override
    public Result next() {
      try {
        Result result = delegate.next();
        if (result == null) {
          return result;
        }
        return decrypt(result);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    public void remove() {
      delegate.remove();
    }
    
  }

  protected class EncryptedResultScanner implements ResultScanner {

    private ResultScanner delegate;

    public EncryptedResultScanner(ResultScanner delegate) {
      this.delegate = delegate;
    }

    @Override
    public Iterator<Result> iterator() {
      return new EncryptedResultIterator(delegate.iterator());
    }

    @Override
    public Result next() throws IOException {
      Result result = delegate.next();
      if (result == null) {
        return result;
      }
      return decrypt(result);
    }

    @Override
    public Result[] next(int nbRows) throws IOException {
      Result[] results = delegate.next(nbRows);
      if (results == null || results.length < 1) {
        return results;
      }
      Result[] transformedResults = new Result[results.length];
      for (int i = 0; i < results.length; i++) {
        transformedResults[i] = decrypt(results[i]);
      }
      return transformedResults;
    }

    @Override
    public void close() {
      delegate.close();
    }

  }

  @Override
  public ResultScanner getScanner(Scan scan) throws IOException {
    checkCryptoContext();
    return new EncryptedResultScanner(super.getScanner(scan));
  }

  @Override
  public ResultScanner getScanner(byte[] family) throws IOException {
    checkCryptoContext();
    return new EncryptedResultScanner(super.getScanner(family));
  }

  @Override
  public ResultScanner getScanner(byte[] family, byte[] qualifier) throws IOException {
    checkCryptoContext();
    return new EncryptedResultScanner(super.getScanner(family, qualifier));
  }

  @Override
  public Result get(Get get) throws IOException {
    checkCryptoContext();
    Result result = super.get(get);
    if (result == null) {
      return result;
    }
    return decrypt(result);
  }

  @Override
  public Result[] get(List<Get> gets) throws IOException {
    checkCryptoContext();
    // Transformations here are handled in the override for batch()
    return super.get(gets);
  }

  @Override
  public Result getRowOrBefore(byte[] row, byte[] family) throws IOException {
    checkCryptoContext();
    Result result = super.getRowOrBefore(row, family);
    if (result == null || result.isEmpty()) {
      return result;
    }
    return decrypt(result);
  }

  @Override
  public void batch(List<? extends Row> actions, Object[] results) throws InterruptedException,
      IOException {
    checkCryptoContext();
    List<Row> transformedActions = new ArrayList<Row>();
    for (Row action: actions) {
      if (action instanceof Put) {
        transformedActions.add(encrypt((Put)action));
      } else if (action instanceof Append) {
        if (inFamilySet((Append)action)) {
          throw new UnsupportedOperationException();
        }
      } else if (action instanceof Increment) {
        if (inFamilySet((Increment)action)) {
          throw new UnsupportedOperationException();
        }
      }
      transformedActions.add(action);
    }
    super.batch(transformedActions, results);
    for (int i = 0; i < results.length; i++) {
      if (results[i] instanceof Result) {
        results[i] = decrypt((Result)results[i]);
      }
    }
  }

  @Override
  public Object[] batch(List<? extends Row> actions) throws InterruptedException, IOException {
    checkCryptoContext();
    List<Row> transformedActions = new ArrayList<Row>();
    for (Row action: actions) {
      if (action instanceof Put) {
        transformedActions.add((Row)encrypt((Put)action));
      } else if (action instanceof Append) {
        if (inFamilySet((Append)action)) {
          throw new UnsupportedOperationException();
        }
      } else if (action instanceof Increment) {
        if (inFamilySet((Increment)action)) {
          throw new UnsupportedOperationException();
        }
      }
      transformedActions.add(action);
    }
    Object[] results = super.batch(transformedActions);
    for (int i = 0; i < results.length; i++) {
      if (results[i] instanceof Result) {
        results[i] = decrypt((Result)results[i]);
      }
    }
    return results;
  }

  @Override
  public void put(Put put) throws IOException {
    checkCryptoContext();
    super.put(encrypt(put));
  }

  @Override
  public void put(List<Put> puts) throws IOException {
    checkCryptoContext();
    List<Put> transformedPuts = new ArrayList<Put>();
    for (Put put: puts) {
      transformedPuts.add(encrypt(put));
    }
    super.put(transformedPuts);
  }

  @Override
  public void mutateRow(RowMutations rm) throws IOException {
    checkCryptoContext();
    RowMutations transformedMutations = new RowMutations(rm.getRow());
    for (Mutation m: rm.getMutations()) {
      if (m instanceof Put) {
        transformedMutations.add(encrypt((Put)m));
      } else if (m instanceof Delete) {
        transformedMutations.add((Delete)m);
      }
    }
    super.mutateRow(transformedMutations);
  }

  @Override
  public Result append(Append append) throws IOException {
    if (inFamilySet(append)) {
      throw new UnsupportedOperationException();
    }
    return super.append(append);
  }

  @Override
  public Result increment(Increment increment) throws IOException {
    if (inFamilySet(increment)) {
      throw new UnsupportedOperationException();
    }
    return super.increment(increment);
  }

  @Override
  public long incrementColumnValue(byte[] row, byte[] family, byte[] qualifier, long amount)
      throws IOException {
    if (inFamilySet(family)) {
      throw new UnsupportedOperationException();
    }
    return super.incrementColumnValue(row, family, qualifier, amount);
  }

  @Override
  public long incrementColumnValue(byte[] row, byte[] family, byte[] qualifier, long amount,
      boolean writeToWAL) throws IOException {
    if (inFamilySet(family)) {
      throw new UnsupportedOperationException();
    }
    return super.incrementColumnValue(row, family, qualifier, amount, writeToWAL);
  }

  @Override
  public boolean checkAndPut(byte[] row, byte[] family, byte[] qualifier, byte[] value, Put put)
      throws IOException {
    if (inFamilySet(family)) {
      throw new UnsupportedOperationException();
    }
    return super.checkAndPut(row, family, qualifier, value, put);
  }

  @Override
  public boolean checkAndDelete(byte[] row, byte[] family, byte[] qualifier, byte[] value,
      Delete delete) throws IOException {
    if (inFamilySet(family)) {
      throw new UnsupportedOperationException();
    }
    return super.checkAndDelete(row, family, qualifier, value, delete);
  }

  /**
   * Add a family to the set of those to be encrypted. By default all families
   * are encrypted; once you invoke this you must specify each and every one.
   * @param family
   */
  public void addFamily(byte[] family) {
    familySet.add(family);
  }

  /**
   * Remove a family from the set of those to be encrypted
   * @param family
   */
  public void removeFamily(byte[] family) {
    familySet.remove(family);
  }

  /**
   * Get a read only view of the set of families to be encrypted
   */
  public Collection<byte[]> getFamilySet() {
    return Collections.unmodifiableSet(familySet);
  }

  /**
   * Supply the set of families to be encrypted. By default all families
   * are encrypted, when you invoke this you must specify each and every one
   * desired.
   */
  public void setFamilySet(Collection<byte[]> families) {
    familySet = new TreeSet<byte[]>(Bytes.BYTES_COMPARATOR);
    familySet.addAll(families);
  }

  /**
   * Get the crypto context for this table
   */
  public Encryption.Context getCryptoContext() {
    return cryptoContext;
  }

  /**
   * Set the crypto context for this table
   */
  public void setCryptoContext(Encryption.Context context) {
    this.cryptoContext = context;
  }
}
