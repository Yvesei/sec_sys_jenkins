import jenkins.model.Jenkins
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy

try {
    println("=" * 80)
    println("BASIC SECURITY INITIALIZATION")
    println("=" * 80)
    
    def instance = Jenkins.getInstance()
    
    // Step 1: Setup security realm
    println("[*] Step 1: Configuring security realm...")
    def realm = new HudsonPrivateSecurityRealm(false, false)
    instance.setSecurityRealm(realm)
    println("    [✓] Security realm configured")
    
    // Step 2: Create admin user with admin:admin credentials
    println("[*] Step 2: Creating admin user...")
    realm.createAccount("admin", "admin")
    println("    [✓] Admin user created")
    println("        Username: admin")
    println("        Password: admin")
    
    // Step 3: Setup authorization
    println("[*] Step 3: Configuring authorization strategy...")
    instance.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy())
    println("    [✓] Authorization configured")
    
    // Step 4: Save and mark setup complete
    println("[*] Step 4: Finalizing setup...")
    instance.setInstallState(Jenkins.installState.INITIAL_SETUP_COMPLETED_MARKER)
    instance.save()
    println("    [✓] Setup complete")
    
    println("=" * 80)
    println("INITIALIZATION SUCCESSFUL")
    println("=" * 80)
    
} catch (Exception e) {
    println("ERROR: ${e.message}")
    e.printStackTrace()
}