/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hbase.security.access;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.filter.FilterBase;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.util.Bytes;

/**
 * <strong>NOTE: for internal use only by AccessController implementation</strong>
 *
 * <p>
 * TODO: There is room for further performance optimization here.
 * Calling TableAuthManager.authorize() per KeyValue imposes a fair amount of
 * overhead.  A more optimized solution might look at the qualifiers where
 * permissions are actually granted and explicitly limit the scan to those.
 * </p>
 * <p>
 * We should aim to use this _only_ when access to the requested column families
 * is not granted at the column family levels.  If table or column family
 * access succeeds, then there is no need to impose the overhead of this filter.
 * </p>
 */
class AccessControlFilter extends FilterBase {

  private TableAuthManager authManager;
  private HRegion region;
  private boolean isMetaTable;
  private User user;

  /**
   * For Writable
   */
  AccessControlFilter() {
  }

  AccessControlFilter(TableAuthManager mgr, User ugi, HRegion region) {
    authManager = mgr;
    this.region = region;
    isMetaTable = Bytes.equals(region.getTableDesc().getName(), HConstants.ROOT_TABLE_NAME) ||
      Bytes.equals(region.getTableDesc().getName(), HConstants.META_TABLE_NAME);
    user = ugi;
  }

  @Override
  public ReturnCode filterKeyValue(KeyValue kv) {
    // Allow everything if a null filter
    if (region == null) {
      return ReturnCode.INCLUDE;
    }
    // Hide all shadow CF KVs
    if (Bytes.equals(kv.getBuffer(), kv.getFamilyOffset(), kv.getFamilyLength(),
      AccessControlLists.ACL_CF_NAME, 0, AccessControlLists.ACL_CF_NAME.length)) {
      return ReturnCode.NEXT_COL;
    }
    if (isMetaTable) {
      return ReturnCode.INCLUDE;
    }
    // Otherwise, check authorization for KV
    // Before per cell ACLs we used to return the NEXT_COL hint, but can no
    // no longer do that since, given the possibility of per cell ACLs
    // anywhere, we now need to examine all KVs with this filter.
    if (authManager.authorize(user, region, kv, true, Permission.Action.READ)) {
      return ReturnCode.INCLUDE;
    }
    return ReturnCode.SKIP;
  }

  @Override
  public void write(DataOutput dataOutput) throws IOException {
    // no implementation, server-side use only
    throw new UnsupportedOperationException(
        "Serialization not supported.  Intended for server-side use only.");
  }

  @Override
  public void readFields(DataInput dataInput) throws IOException {
    // no implementation, server-side use only
    throw new UnsupportedOperationException(
        "Serialization not supported.  Intended for server-side use only.");
  }
}
