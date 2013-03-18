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

package org.apache.hadoop.hbase.security.access;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.hadoop.hbase.protobuf.ProtobufUtil;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.io.Writable;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;

/**
 * An iterable list of user table permissions.
 */
public class UserTablePermissions implements Writable {
  private ListMultimap<String,TablePermission> perms = ArrayListMultimap.create();

  /**
   * Nullary constructor
   */
  public UserTablePermissions() { }

  /**
   * Constructor
   * @param user The user
   * @param perms Initial permissions list
   */
  public UserTablePermissions(String user, Collection<TablePermission> perms) {
    this.perms.putAll(user, perms);
  }

  /**
   * Constructor
   * @param user The user
   * @param perms Initial permissions list
   */
  public UserTablePermissions(User user, Collection<TablePermission> perms) {
    this(user.getShortName(), perms);
  }

  /**
   * Constructor
   * @param perms Initial permissions list
   */
  public UserTablePermissions(ListMultimap<String, TablePermission> perms) {
    this.perms = perms;
  }

  /**
   * Constructor
   * @param bytes Buffer containing serialized Writable representation
   * @param offset Offset in bytes buffer
   * @param length Length of serialized data in bytes buffer
   * @throws IOException
   */
  public UserTablePermissions(byte[] bytes, int offset, int length) throws IOException {
    this.readFields(new DataInputStream(new ByteArrayInputStream(bytes, offset, length)));
  }

  /**
   * Add a permission to the permission list.
   * @param user The user
   * @param p The permission to add
   * @return this
   */
  public UserTablePermissions add(String user, TablePermission p) {
    this.perms.put(user, p);
    return this;
  }

  /**
   * Add a permission to the permission list.
   * @param user The user
   * @param p The permission to add
   * @return this
   */
  public UserTablePermissions add(User user, TablePermission p) {
    return add(user.getShortName(), p);
  }

  /**
   * Add permissions to the permission list
   * @param user The user
   * @param perms The permissions to add
   * @return this
   */
  public UserTablePermissions addAll(String user, Iterable<? extends TablePermission> perms) {
    this.perms.putAll(user, perms);
    return this;
  }

  /**
   * Add permissions to the permission list
   * @param user The user
   * @param perms The permissions to add
   * @return this
   */
  public UserTablePermissions addAll(User user, Iterable<? extends TablePermission> perms) {
    return addAll(user.getShortName(), perms);
  }

  /**
   * Remove a permission from the permission list.
   * @param user The user
   * @param p The permission to remove
   * @return this
   */
  public UserTablePermissions remove(String user, TablePermission p) {
    List<TablePermission> l = perms.get(user);
    if (l != null) {
      l.remove(p);
    }
    return this;
  }

  /**
   * Remove a permission from the permission list.
   * @param user The user
   * @param p The permission to remove
   * @return this
   */
  public UserTablePermissions remove(User user, TablePermission p) {
    return remove(user.getShortName(), p);
  }

  /**
   * Remove all permissions for a user.
   * @param user The user
   * @return this
   */
  public UserTablePermissions removeAll(String user) {
    perms.removeAll(user);
    return this;
  }

  /**
   * Remove all permissions for a user.
   * @param user The user
   * @return this
   */
  public UserTablePermissions removeAll(User user) {
    return removeAll(user.getShortName());
  }

  /**
   * Remove all permissions.
   */
  public void clear() {
    perms.clear();
  }

  /**
   * Get all permissions for a user.
   * @param user The user
   * @return The permissions
   */
  public List<TablePermission> get(String user) {
    return perms.get(user);
  }

  /**
   * Get all permissions for a user.
   * @param user The user
   * @return The permissions
   */
  public List<TablePermission> get(User user) {
    return get(user.getShortName());
  }

  /**
   * @return A multimap of user table permissions
   */
  public ListMultimap<String, TablePermission> asMultimap() {
    return perms;
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    int numUsers = in.readInt();
    for (int i = 0; i < numUsers; i++) {
      String user = in.readUTF();
      int numPerms = in.readInt();
      for (int j = 0; j < numPerms; j++) {
        TablePermission p = new TablePermission();
        p.readFields(in);
        perms.put(user, p);
      }
    }
  }

  @Override
  public void write(DataOutput out) throws IOException {
    Set<String> users = perms.keySet();
    out.writeInt(users.size());
    for (String user: users) {
      out.writeUTF(user);
      List<TablePermission> l = perms.get(user);
      if (l != null) {
        out.writeInt(l.size());
        for (TablePermission p: l) {
          p.write(out);
        }
      } else {
        out.writeInt(0);
      }
    }
  }

  /**
   * Rehydrate a serialized representation of UserTablePermissions
   * @param bytes the serialized bytes
   * @return
   * @throws IOException
   */
  public static UserTablePermissions fromBytes(byte[] bytes,
      int offset, int length) throws IOException {
    UserTablePermissions perms = new UserTablePermissions();
    // We will need to be backwards compatible with any 0.94 version of this
    // that will use Writables
    if (ProtobufUtil.isPBMagicPrefix(bytes, offset, length)) {
      int pblen = ProtobufUtil.lengthOfPBMagic();
      return new UserTablePermissions(ProtobufUtil.toUserTablePermissions(
        AccessControlProtos.UserTablePermissions.newBuilder()
          .mergeFrom(bytes, offset + pblen, length - pblen).build()));
    } else {
      perms.readFields(new DataInputStream(new ByteArrayInputStream(bytes,
        offset, length)));
    }
    return perms;
  }

  /**
   * Produce a serialized representation
   * @throws IOException
   */
  public static byte[] toBytes(UserTablePermissions tablePerms)
      throws IOException {
    return ProtobufUtil.prependPBMagic(
      ProtobufUtil.toUserTablePermissions(tablePerms).toByteArray());
  }
}
