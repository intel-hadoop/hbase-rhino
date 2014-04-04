package org.apache.hadoop.hbase.security;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.hadoop.hbase.protobuf.generated.AdminProtos;
import org.apache.hadoop.hbase.protobuf.generated.ClientProtos;
import org.apache.hadoop.hbase.protobuf.generated.RegionServerStatusProtos;
import org.apache.hadoop.hbase.protobuf.generated.AuthenticationProtos.TokenIdentifier.Kind;
import org.apache.hadoop.hbase.protobuf.generated.MasterProtos.MasterService;

public class SecurityTokenAuthInfo extends SecurityInfo {
  
  /** Maps RPC service names to authentication information */
  private static ConcurrentMap<String,SecurityTokenAuthInfo> tokenAuthInfos = new ConcurrentHashMap<String,SecurityTokenAuthInfo>();
  
  static {
    tokenAuthInfos.put(AdminProtos.AdminService.getDescriptor().getName(),
        new SecurityTokenAuthInfo("hbase.regionserver.tokenauth.principal", Kind.HBASE_AUTH_TOKEN));
    tokenAuthInfos.put(ClientProtos.ClientService.getDescriptor().getName(),
        new SecurityTokenAuthInfo("hbase.regionserver.tokenauth.principal", Kind.HBASE_AUTH_TOKEN));
    tokenAuthInfos.put(MasterService.getDescriptor().getName(),
        new SecurityTokenAuthInfo("hbase.master.tokenauth.principal", Kind.HBASE_AUTH_TOKEN));
    tokenAuthInfos.put(RegionServerStatusProtos.RegionServerStatusService.getDescriptor().getName(),
        new SecurityTokenAuthInfo("hbase.master.tokenauth.principal", Kind.HBASE_AUTH_TOKEN));
  }
  
  /**
   * Adds a security configuration for a new service name.  Note that this will have no effect if
   * the service name was already registered.
   */
  public static void addInfo(String serviceName, SecurityTokenAuthInfo tokenAuthenticationInfo) {
    tokenAuthInfos.putIfAbsent(serviceName, tokenAuthenticationInfo);
  }

  /**
   * Returns the security configuration associated with the given service name.
   */
  public static SecurityTokenAuthInfo getInfo(String serviceName) {
    return tokenAuthInfos.get(serviceName);
  }
  
  private final String serverPrincipal;
  private final Kind tokenKind;
  
  /** Maps RPC service names to authentication information */
  public SecurityTokenAuthInfo(String serverPrincipal, Kind tokenKind) {
    super(serverPrincipal,tokenKind);
    this.serverPrincipal = serverPrincipal;
    this.tokenKind = tokenKind;    
  }

}
