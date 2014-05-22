package org.apache.hadoop.hbase.conf;

/** 
 * <p>
 * This class contains constants for configuration keys used
 * in the hbase server code.
 *</p>
 */
public class ServerConfigurationKeys {

    /** Enable/Disable ssl for http server */
    public static final String HBASE_SSL_ENABLED_KEY = "hbase.ssl.enabled";
    public static final boolean HBASE_SSL_ENABLED_DEFAULT = false;

    /** Enable/Disable aliases serving from jetty */
    public static final String HBASE_JETTY_LOGS_SERVE_ALIASES =
      "hbase.jetty.logs.serve.aliases";
    public static final boolean DEFAULT_HBASE_JETTY_LOGS_SERVE_ALIASES =
      true;

}
