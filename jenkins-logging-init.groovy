import jenkins.model.Jenkins
import java.util.logging.Logger
import java.util.logging.Level

println("="*80)
println("COMPREHENSIVE LOGGING INITIALIZATION")
println("="*80)

try {
    // Create log directory
    def logDir = new File("/var/log/jenkins")
    if (!logDir.exists()) {
        logDir.mkdirs()
        println("    [✓] Created log directory: /var/log/jenkins")
    }
    
    // Enable verbose logging for various Jenkins components
    println("[*] Configuring verbose logging...")
    
    // Enable DEBUG level logging for HTTP requests
    Logger.getLogger("org.eclipse.jetty").setLevel(Level.ALL)
    Logger.getLogger("hudson").setLevel(Level.FINE)
    Logger.getLogger("jenkins").setLevel(Level.FINE)
    
    // Enable request/response logging
    System.setProperty("org.eclipse.jetty.LEVEL", "DEBUG")
    System.setProperty("org.eclipse.jetty.server.LEVEL", "DEBUG")
    System.setProperty("org.eclipse.jetty.server.Request.LEVEL", "DEBUG")
    
    println("    [✓] Verbose logging enabled for Jetty and Jenkins")
    println("    [✓] Log level set to FINE/DEBUG")
    
    println("="*80)
    println("LOGGING CONFIGURATION COMPLETE")
    println("="*80)
    
} catch (Exception e) {
    println("Error setting up logging: " + e.message)
    e.printStackTrace()
}