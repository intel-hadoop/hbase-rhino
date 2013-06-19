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

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.zookeeper.ZooKeeperWatcher;
import org.apache.zookeeper.KeeperException;

import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * Performs authorization checks for a given user's assigned permissions
 */
public class TableAuthManager {
  private static class PermissionCache<T extends Permission> {
    /** Cache of user permissions */
    private ListMultimap<String,T> userCache = ArrayListMultimap.create();
    /** Cache of group permissions */
    private ListMultimap<String,T> groupCache = ArrayListMultimap.create();

    public List<T> getUser(String user) {
      return userCache.get(user);
    }

    public void putUser(String user, T perm) {
      userCache.put(user, perm);
    }

    public List<T> replaceUser(String user, Iterable<? extends T> perms) {
      return userCache.replaceValues(user, perms);
    }

    public List<T> getGroup(String group) {
      return groupCache.get(group);
    }

    public void putGroup(String group, T perm) {
      groupCache.put(group, perm);
    }

    public List<T> replaceGroup(String group, Iterable<? extends T> perms) {
      return groupCache.replaceValues(group, perms);
    }

    /**
     * Returns a combined map of user and group permissions, with group names prefixed by
     * {@link AccessControlLists#GROUP_PREFIX}.
     */
    public ListMultimap<String,T> getAllPermissions() {
      ListMultimap<String,T> tmp = ArrayListMultimap.create();
      tmp.putAll(userCache);
      for (String group : groupCache.keySet()) {
        tmp.putAll(AccessControlLists.GROUP_PREFIX + group, groupCache.get(group));
      }
      return tmp;
    }
  }

  private static Log LOG = LogFactory.getLog(TableAuthManager.class);

  private static TableAuthManager instance;

  /** Cache of global permissions */
  private volatile PermissionCache<Permission> globalCache;

  private ConcurrentSkipListMap<byte[], PermissionCache<TablePermission>> tableCache =
      new ConcurrentSkipListMap<byte[], PermissionCache<TablePermission>>(Bytes.BYTES_COMPARATOR);

  private Configuration conf;
  private ZKPermissionWatcher zkperms;

  private TableAuthManager(ZooKeeperWatcher watcher, Configuration conf)
      throws IOException {
    this.conf = conf;

    // initialize global permissions based on configuration
    globalCache = initGlobal(conf);

    this.zkperms = new ZKPermissionWatcher(watcher, this, conf);
    try {
      this.zkperms.start();
    } catch (KeeperException ke) {
      LOG.error("ZooKeeper initialization failed", ke);
    }
  }

  /**
   * Returns a new {@code PermissionCache} initialized with permission assignments
   * from the {@code hbase.superuser} configuration key.
   */
  private PermissionCache<Permission> initGlobal(Configuration conf) throws IOException {
    User user = User.getCurrent();
    if (user == null) {
      throw new IOException("Unable to obtain the current user, " +
          "authorization checks for internal operations will not work correctly!");
    }
    PermissionCache<Permission> newCache = new PermissionCache<Permission>();
    String currentUser = user.getShortName();

    // the system user is always included
    List<String> superusers = Lists.asList(currentUser, conf.getStrings(
        AccessControlLists.SUPERUSER_CONF_KEY, new String[0]));
    if (superusers != null) {
      for (String name : superusers) {
        if (AccessControlLists.isGroupPrincipal(name)) {
          newCache.putGroup(AccessControlLists.getGroupName(name),
              new Permission(Permission.Action.values()));
        } else {
          newCache.putUser(name, new Permission(Permission.Action.values()));
        }
      }
    }
    return newCache;
  }

  public ZKPermissionWatcher getZKPermissionWatcher() {
    return this.zkperms;
  }

  public void refreshCacheFromWritable(byte[] table, byte[] data) throws IOException {
    if (data != null && data.length > 0) {
      DataInput in = new DataInputStream(new ByteArrayInputStream(data));
      ListMultimap<String,TablePermission> perms = AccessControlLists.readPermissions(in, conf);
      if (perms != null) {
        if (Bytes.equals(table, AccessControlLists.ACL_GLOBAL_NAME)) {
          updateGlobalCache(perms);
        } else {
          updateTableCache(table, perms);
        }
      }
    } else {
      LOG.debug("Skipping permission cache refresh because writable data is empty");
    }
  }

  /**
   * Updates the internal global permissions cache
   *
   * @param userPerms
   */
  private void updateGlobalCache(ListMultimap<String,TablePermission> userPerms) {
    PermissionCache<Permission> newCache = null;
    try {
      newCache = initGlobal(conf);
      for (Map.Entry<String,TablePermission> entry : userPerms.entries()) {
        if (AccessControlLists.isGroupPrincipal(entry.getKey())) {
          newCache.putGroup(AccessControlLists.getGroupName(entry.getKey()),
              new Permission(entry.getValue().getActions()));
        } else {
          newCache.putUser(entry.getKey(), new Permission(entry.getValue().getActions()));
        }
      }
      globalCache = newCache;
    } catch (IOException e) {
      // Never happens
      LOG.error("Error occured while updating the global cache", e);
    }
  }

  /**
   * Updates the internal permissions cache for a single table, splitting
   * the permissions listed into separate caches for users and groups to optimize
   * group lookups.
   * 
   * @param table
   * @param tablePerms
   */
  private void updateTableCache(byte[] table, ListMultimap<String,TablePermission> tablePerms) {
    PermissionCache<TablePermission> newTablePerms = new PermissionCache<TablePermission>();

    for (Map.Entry<String,TablePermission> entry : tablePerms.entries()) {
      if (AccessControlLists.isGroupPrincipal(entry.getKey())) {
        newTablePerms.putGroup(AccessControlLists.getGroupName(entry.getKey()), entry.getValue());
      } else {
        newTablePerms.putUser(entry.getKey(), entry.getValue());
      }
    }

    tableCache.put(table, newTablePerms);
  }

  private PermissionCache<TablePermission> getTablePermissions(byte[] table) {
    if (!tableCache.containsKey(table)) {
      tableCache.putIfAbsent(table, new PermissionCache<TablePermission>());
    }
    return tableCache.get(table);
  }

  /**
   * Authorizes a global permission
   * @param perms
   * @param action
   * @return
   */
  private boolean authorize(List<Permission> perms, Permission.Action action) {
    if (perms != null) {
      for (Permission p : perms) {
        if (p.implies(action)) {
          return true;
        }
      }
    } else if (LOG.isTraceEnabled()) {
      LOG.trace("No permissions found");
    }

    return false;
  }

  /**
   * Authorize a global permission based on ACLs for the given user and the
   * user's groups.
   * @param user
   * @param action
   * @return
   */
  public boolean authorize(User user, Permission.Action action) {
    if (user == null) {
      return false;
    }

    if (authorize(globalCache.getUser(user.getShortName()), action)) {
      return true;
    }

    String[] groups = user.getGroupNames();
    if (groups != null) {
      for (String group : groups) {
        if (authorize(globalCache.getGroup(group), action)) {
          return true;
        }
      }
    }
    return false;
  }

  private boolean authorize(List<TablePermission> perms, byte[] table, byte[] family,
      Permission.Action action) {
    return authorize(perms, table, family, null, action);
  }

  private boolean authorize(List<TablePermission> perms, byte[] table, byte[] family,
      byte[] qualifier, Permission.Action action) {
    if (perms != null) {
      for (TablePermission p : perms) {
        if (p.implies(table, family, qualifier, action)) {
          return true;
        }
      }
    } else if (LOG.isTraceEnabled()) {
      LOG.trace("No permissions found for table="+Bytes.toStringBinary(table));
    }
    return false;
  }

  public List<TablePermission> getCellPermissionsForUser(HRegion region, User user,
      KeyValue kv) throws IOException {
    byte[] qualifier = AccessControlLists.getQualifierFor(kv);
    Get get = new Get(kv.getRow())
      .addColumn(AccessControlLists.ACL_CF_NAME, qualifier)
      .setMaxVersions(1)
      .setFilter(new AccessControlFilter()); // set null ACF to avoid recursive checks
    long ts = kv.getTimestamp();
    if (ts != HConstants.LATEST_TIMESTAMP) {
      get.setTimeRange(0L, ts + 1);
    }
    KeyValue aclKV = region.get(get)
      .getColumnLatest(AccessControlLists.ACL_CF_NAME, qualifier);
    if (aclKV != null) {
      UserTablePermissions cellPerms =
        UserTablePermissions.fromBytes(aclKV.getBuffer(), aclKV.getValueOffset(),
          aclKV.getValueLength());
      List<TablePermission> perms = Lists.newArrayList();
      // Get perms for the user from the cell ACL
      List<TablePermission> userPerms = cellPerms.get(user.getShortName());
      if (userPerms != null) {
        perms.addAll(userPerms);
      }
      // Get perms for the user's groups from the cell ACL
      String groupNames[] = user.getGroupNames();
      for (String group: groupNames) {
        List<TablePermission> groupPerms =
          cellPerms.get(AccessControlLists.GROUP_PREFIX + group);
        if (groupPerms != null) {
          perms.addAll(groupPerms);
        }
      }
      return !perms.isEmpty() ? perms : null;
    }
    return null;
  }

  /**
   * Authorize a user for a given KV. This is called from AccessControlFilter.
   */
  public boolean authorize(User user, HRegion region, KeyValue kv,
    boolean checkCachedPerms, Permission.Action action) {
    byte[] tableName = region.getTableDesc().getName();
    boolean isCatalogTable = Bytes.equals(HConstants.ROOT_TABLE_NAME, tableName) ||
      Bytes.equals(HConstants.META_TABLE_NAME, tableName);

    // Special case handling for catalog tables
    if (action == Permission.Action.READ && isCatalogTable) {
      return true;
    }

    // Are there permissions for this user for this KV?
    if (!isCatalogTable) try {
      List<TablePermission> perms = getCellPermissionsForUser(region, user, kv);
      if (perms != null) {
        for (Permission p: perms) {
          if (p.implies(action)) {
            if (LOG.isTraceEnabled()) {
              LOG.trace("Action " + action + " allowed for user " +
                user.getShortName() + " for kv " + kv);
            }
            return true;
          }
        }
      }
     } catch (IOException e) {
      LOG.error("Failed parse of ACLs for KV " + kv.toString(), e);
      // Fall through to check with the table and CF perms we were able
      // to collect regardless
     }
    if (LOG.isTraceEnabled()) {
      LOG.trace("No perms for user " + user.getShortName() + " for kv " + kv);
    }

    // No, can we apply cached CF and table level perms?
    if (checkCachedPerms) {
      byte[] family = kv.getFamily();
      byte[] qualifier = kv.getQualifier();
      // User is authorized at table or CF level
      if (authorizeUser(user.getShortName(), tableName, family,
          qualifier, action)) {
        if (LOG.isTraceEnabled()) {
          LOG.trace("User " + user.getShortName() + " is authorized");
        }
        return true;
      }
      String groupNames[] = user.getGroupNames();
      if (groupNames != null) {
        for (String group: groupNames) {
          // TODO: authorizeGroup should check qualifier too?
          // Group is authorized at table or CF level
          if (authorizeGroup(group, tableName, family, action)) {
            if (LOG.isTraceEnabled()) {
              LOG.trace("Group " + group + " is authorized");
            }
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Checks global authorization for a specific action for a user, based on the
   * stored user permissions.
   */
  public boolean authorizeUser(String username, Permission.Action action) {
    return authorize(globalCache.getUser(username), action);
  }

  /**
   * Checks authorization to a given table and column family for a user, based on the
   * stored user permissions.
   *
   * @param username
   * @param table
   * @param family
   * @param action
   * @return
   */
  public boolean authorizeUser(String username, byte[] table, byte[] family,
      Permission.Action action) {
    return authorizeUser(username, table, family, null, action);
  }

  public boolean authorizeUser(String username, byte[] table, byte[] family,
      byte[] qualifier, Permission.Action action) {
    // global authorization supercedes table level
    if (authorizeUser(username, action)) {
      return true;
    }
    return authorize(getTablePermissions(table).getUser(username), table, family,
        qualifier, action);
  }


  /**
   * Checks authorization for a given action for a group, based on the stored
   * permissions.
   */
  public boolean authorizeGroup(String groupName, Permission.Action action) {
    return authorize(globalCache.getGroup(groupName), action);
  }

  /**
   * Checks authorization to a given table and column family for a group, based
   * on the stored permissions. 
   * @param groupName
   * @param table
   * @param family
   * @param action
   * @return
   */
  public boolean authorizeGroup(String groupName, byte[] table, byte[] family,
      Permission.Action action) {
    // global authorization supercedes table level
    if (authorizeGroup(groupName, action)) {
      return true;
    }
    return authorize(getTablePermissions(table).getGroup(groupName), table, family, action);
  }

  public boolean authorize(User user, byte[] table, byte[] family,
      byte[] qualifier, Permission.Action action) {
    if (authorizeUser(user.getShortName(), table, family, qualifier, action)) {
      return true;
    }

    String[] groups = user.getGroupNames();
    if (groups != null) {
      for (String group : groups) {
        if (authorizeGroup(group, table, family, action)) {
          return true;
        }
      }
    }
    return false;
  }

  public boolean authorize(User user, byte[] table, byte[] family,
      Permission.Action action) {
    return authorize(user, table, family, null, action);
  }

  /**
   * Returns true if the given user has a {@link TablePermission} matching up
   * to the column family portion of a permission.  Note that this permission
   * may be scoped to a given column qualifier and does not guarantee that
   * authorize() on the same column family would return true.
   */
  public boolean matchPermission(User user,
      byte[] table, byte[] family, TablePermission.Action action) {
    PermissionCache<TablePermission> tablePerms = tableCache.get(table);
    if (tablePerms != null) {
      List<TablePermission> userPerms = tablePerms.getUser(user.getShortName());
      if (userPerms != null) {
        for (TablePermission p : userPerms) {
          if (p.matchesFamily(table, family, action)) {
            return true;
          }
        }
      }

      String[] groups = user.getGroupNames();
      if (groups != null) {
        for (String group : groups) {
          List<TablePermission> groupPerms = tablePerms.getGroup(group);
          if (groupPerms != null) {
            for (TablePermission p : groupPerms) {
              if (p.matchesFamily(table, family, action)) {
                return true;
              }
            }
          }
        }
      }
    }

    return false;
  }

  public boolean matchPermission(User user,
      byte[] table, byte[] family, byte[] qualifier,
      TablePermission.Action action) {
    PermissionCache<TablePermission> tablePerms = tableCache.get(table);
    if (tablePerms != null) {
      List<TablePermission> userPerms = tablePerms.getUser(user.getShortName());
      if (userPerms != null) {
        for (TablePermission p : userPerms) {
          if (p.matchesFamilyQualifier(table, family, qualifier, action)) {
            return true;
          }
        }
      }

      String[] groups = user.getGroupNames();
      if (groups != null) {
        for (String group : groups) {
          List<TablePermission> groupPerms = tablePerms.getGroup(group);
          if (groupPerms != null) {
            for (TablePermission p : groupPerms) {
              if (p.matchesFamilyQualifier(table, family, qualifier, action)) {
                return true;
              }
            }
          }
        }
      }
    }

    return false;
  }

  public void remove(byte[] table) {
    tableCache.remove(table);
  }

  /**
   * Overwrites the existing permission set for a given user for a table, and
   * triggers an update for zookeeper synchronization.
   * @param username
   * @param table
   * @param perms
   */
  public void setUserPermissions(String username, byte[] table,
      List<TablePermission> perms) {
    PermissionCache<TablePermission> tablePerms = getTablePermissions(table);
    tablePerms.replaceUser(username, perms);
    writeToZooKeeper(table, tablePerms);
  }

  /**
   * Overwrites the existing permission set for a group and triggers an update
   * for zookeeper synchronization.
   * @param group
   * @param table
   * @param perms
   */
  public void setGroupPermissions(String group, byte[] table,
      List<TablePermission> perms) {
    PermissionCache<TablePermission> tablePerms = getTablePermissions(table);
    tablePerms.replaceGroup(group, perms);
    writeToZooKeeper(table, tablePerms);
  }

  public void writeToZooKeeper(byte[] table,
      PermissionCache<TablePermission> tablePerms) {
    byte[] serialized = new byte[0];
    if (tablePerms != null) {
      serialized = AccessControlLists.writePermissionsAsBytes(tablePerms.getAllPermissions(), conf);
    }
    zkperms.writeToZookeeper(table, serialized);
  }

  static Map<ZooKeeperWatcher,TableAuthManager> managerMap =
    new HashMap<ZooKeeperWatcher,TableAuthManager>();

  public synchronized static TableAuthManager get(
      ZooKeeperWatcher watcher, Configuration conf) throws IOException {
    instance = managerMap.get(watcher);
    if (instance == null) {
      instance = new TableAuthManager(watcher, conf);
      managerMap.put(watcher, instance);
    }
    return instance;
  }
}
