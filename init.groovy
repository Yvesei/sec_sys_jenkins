import jenkins.model.Jenkins
import javax.servlet.*
import javax.servlet.http.*
import java.io.*

println("="*80)
println("COMPREHENSIVE REQUEST LOGGING SETUP")
println("="*80)

try {
    def jenkins = Jenkins.getInstance()
    def pluginManager = jenkins.getPluginManager()
    def plugin = pluginManager.getPlugin("workflow-job")
    
    // Get the servlet context
    def servletContext = jenkins.servletContext
    
    println("[*] Installing comprehensive request logging filter...")
    
    // Create a custom filter for detailed logging
    class DetailedRequestLoggingFilter implements Filter {
        private PrintWriter logWriter
        
        void init(FilterConfig config) {
            def logFile = new File("/var/log/jenkins/detailed-access.log")
            logFile.parentFile.mkdirs()
            logWriter = new PrintWriter(new FileWriter(logFile, true), true)
            println("    [✓] Detailed access log initialized: ${logFile.absolutePath}")
        }
        
        void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
            if (req instanceof HttpServletRequest && res instanceof HttpServletResponse) {
                def request = (HttpServletRequest) req
                def response = (HttpServletResponse) res
                
                def timestamp = new Date().format("yyyy-MM-dd HH:mm:ss.SSS")
                def logEntry = new StringBuilder()
                
                logEntry.append("\n").append("="*120).append("\n")
                logEntry.append("TIMESTAMP: ${timestamp}\n")
                logEntry.append("="*120).append("\n")
                
                // Request Line
                logEntry.append("METHOD: ${request.method}\n")
                logEntry.append("URI: ${request.requestURI}\n")
                logEntry.append("URL: ${request.requestURL}\n")
                logEntry.append("QUERY STRING: ${request.queryString ?: 'NONE'}\n")
                logEntry.append("PROTOCOL: ${request.protocol}\n")
                logEntry.append("SCHEME: ${request.scheme}\n")
                logEntry.append("\n")
                
                // Client Information
                logEntry.append("CLIENT IP: ${request.remoteAddr}\n")
                logEntry.append("CLIENT HOST: ${request.remoteHost}\n")
                logEntry.append("CLIENT PORT: ${request.remotePort}\n")
                logEntry.append("SERVER NAME: ${request.serverName}\n")
                logEntry.append("SERVER PORT: ${request.serverPort}\n")
                logEntry.append("\n")
                
                // All Headers
                logEntry.append("HEADERS:\n")
                logEntry.append("-"*120).append("\n")
                request.headerNames.each { headerName ->
                    def values = request.getHeaders(headerName).toList()
                    values.each { value ->
                        logEntry.append("  ${headerName}: ${value}\n")
                    }
                }
                logEntry.append("\n")
                
                // Query Parameters
                if (request.queryString) {
                    logEntry.append("QUERY PARAMETERS:\n")
                    logEntry.append("-"*120).append("\n")
                    request.parameterMap.each { key, values ->
                        values.each { value ->
                            logEntry.append("  ${key} = ${value}\n")
                        }
                    }
                    logEntry.append("\n")
                }
                
                // POST Parameters (if form data)
                if (request.method == "POST" && request.contentType?.contains("application/x-www-form-urlencoded")) {
                    logEntry.append("POST PARAMETERS:\n")
                    logEntry.append("-"*120).append("\n")
                    request.parameterMap.each { key, values ->
                        values.each { value ->
                            logEntry.append("  ${key} = ${value}\n")
                        }
                    }
                    logEntry.append("\n")
                }
                
                // Cookies
                if (request.cookies) {
                    logEntry.append("COOKIES:\n")
                    logEntry.append("-"*120).append("\n")
                    request.cookies.each { cookie ->
                        logEntry.append("  ${cookie.name} = ${cookie.value}\n")
                    }
                    logEntry.append("\n")
                }
                
                // Session Info
                def session = request.getSession(false)
                if (session) {
                    logEntry.append("SESSION:\n")
                    logEntry.append("-"*120).append("\n")
                    logEntry.append("  Session ID: ${session.id}\n")
                    logEntry.append("  Creation Time: ${new Date(session.creationTime)}\n")
                    logEntry.append("  Last Accessed: ${new Date(session.lastAccessedTime)}\n")
                    logEntry.append("\n")
                }
                
                // User Information
                logEntry.append("AUTHENTICATION:\n")
                logEntry.append("-"*120).append("\n")
                logEntry.append("  Remote User: ${request.remoteUser ?: 'ANONYMOUS'}\n")
                logEntry.append("  Auth Type: ${request.authType ?: 'NONE'}\n")
                logEntry.append("  User Principal: ${request.userPrincipal?.name ?: 'NONE'}\n")
                logEntry.append("\n")
                
                // Content Information
                logEntry.append("CONTENT:\n")
                logEntry.append("-"*120).append("\n")
                logEntry.append("  Content Type: ${request.contentType ?: 'NONE'}\n")
                logEntry.append("  Content Length: ${request.contentLength}\n")
                logEntry.append("  Character Encoding: ${request.characterEncoding ?: 'NONE'}\n")
                
                // Write to log
                logWriter.println(logEntry.toString())
                logWriter.flush()
            }
            
            // Continue with the request
            chain.doFilter(req, res)
        }
        
        void destroy() {
            if (logWriter) {
                logWriter.close()
            }
        }
    }
    
    // Register the filter
    def filter = new DetailedRequestLoggingFilter()
    def filterConfig = [
        getFilterName: { -> "DetailedRequestLoggingFilter" },
        getServletContext: { -> servletContext },
        getInitParameter: { String name -> null },
        getInitParameterNames: { -> Collections.emptyEnumeration() }
    ] as FilterConfig
    
    filter.init(filterConfig)
    
    println("    [✓] Comprehensive request logging filter installed")
    println("    [✓] Detailed logs will be written to: /var/log/jenkins/detailed-access.log")
    
    println("="*80)
    println("REQUEST LOGGING SETUP COMPLETE")
    println("="*80)
    
} catch (Exception e) {
    println("Error setting up request logging: " + e.message)
    e.printStackTrace()
}