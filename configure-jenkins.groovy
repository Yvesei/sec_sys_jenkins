import jenkins.model.Jenkins
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import jenkins.install.InstallState

println("="*60)
println("Starting Jenkins Automated Configuration")
println("="*60)

try {
    def jenkins = Jenkins.getInstance()
    
    println("[1] Setting up security realm...")
    def realm = jenkins.getSecurityRealm()
    
    if (!(realm instanceof HudsonPrivateSecurityRealm)) {
        println("    Creating HudsonPrivateSecurityRealm...")
        realm = new HudsonPrivateSecurityRealm(false, false)
        jenkins.setSecurityRealm(realm)
    }
    
    println("[2] Creating admin user...")
    def user = realm.getUser("admin")
    if (user == null) {
        realm.createAccount("admin", "admin")
        println("    ✓ Admin user created (username: admin, password: admin)")
    } else {
        println("    ✓ Admin user already exists")
    }
    
    println("[3] Configuring authorization strategy...")
    def authStrategy = jenkins.getAuthorizationStrategy()
    if (!(authStrategy instanceof FullControlOnceLoggedInAuthorizationStrategy)) {
        jenkins.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy())
        println("    ✓ Authorization strategy updated")
    }
    
    println("[4] Marking setup as complete...")
    jenkins.setInstallState(InstallState.INITIAL_SETUP_COMPLETED)

    
    println("[5] Saving configuration...")
    jenkins.save()
    
    println("="*60)
    println("✓ Jenkins Configuration Complete!")
    println("="*60)
    println("Admin User: admin")
    println("Admin Password: admin")
    println("="*60)
    
} catch (Exception e) {
    println("[ERROR] Configuration failed: " + e.message)
    e.printStackTrace()
}