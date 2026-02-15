#!/usr/bin/env python3
import requests
import time
import random
import sys
from urllib.parse import urljoin
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class JenkinsNormalUser:
    def __init__(self, jenkins_url):
        self.jenkins_url = jenkins_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Normal user endpoints
        self.normal_endpoints = [
            '/',
            '/api/json',
            '/queue/api/json',
            '/manage',
            '/view/all',
            '/asynchPeople',
            '/log/all',
            '/systemInfo',
        ]
        
        # Job operations
        self.job_endpoints = [
            '/job/test-job/build',
            '/job/test-job/console',
            '/job/test-job/lastBuild/console',
            '/job/test-job/api/json',
        ]
    
    def get_home(self):
        """View Jenkins home page"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/", timeout=5)
            print(f"[*] GET / - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing home: {e}")
            return False
    
    def view_queue(self):
        """Check build queue"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/queue/api/json", timeout=5)
            print(f"[*] GET /queue/api/json - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing queue: {e}")
            return False
    
    def view_jobs(self):
        """View available jobs"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/api/json", timeout=5)
            print(f"[*] GET /api/json - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing jobs: {e}")
            return False
    
    def view_system_info(self):
        """Check system information"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/systemInfo", timeout=5)
            print(f"[*] GET /systemInfo - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing system info: {e}")
            return False
    
    def view_people(self):
        """View people/users"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/asynchPeople", timeout=5)
            print(f"[*] GET /asynchPeople - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing people: {e}")
            return False
    
    def view_manage(self):
        """View manage page"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/manage", timeout=5)
            print(f"[*] GET /manage - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing manage: {e}")
            return False
    
    def search_jobs(self, search_term="test"):
        """Search for jobs"""
        try:
            params = {'q': search_term}
            resp = self.session.get(f"{self.jenkins_url}/search/", params=params, timeout=5)
            print(f"[*] GET /search?q={search_term} - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error searching jobs: {e}")
            return False
    
    def view_logs(self):
        """View system logs"""
        try:
            resp = self.session.get(f"{self.jenkins_url}/log/all", timeout=5)
            print(f"[*] GET /log/all - Status: {resp.status_code}")
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Error accessing logs: {e}")
            return False
    
    def normal_activity_sequence(self):
        """Perform a normal sequence of user activities"""
        activities = [
            self.get_home,
            self.view_queue,
            self.view_jobs,
            self.search_jobs,
            self.view_people,
            self.view_system_info,
            self.view_logs,
            self.view_manage,
        ]
        
        # Randomly select activities to simulate normal browsing
        selected = random.sample(activities, random.randint(3, 6))
        
        for activity in selected:
            try:
                activity()
                # Random delay between 2-8 seconds (normal user reading time)
                delay = random.uniform(2, 8)
                time.sleep(delay)
            except Exception as e:
                print(f"[!] Activity error: {e}")
    
    def run_infinite_loop(self):
        """Run normal user activity in infinite loop"""
        print(f"[*] Starting normal user activity against {self.jenkins_url}")
        print("[*] Running infinite loop with realistic delays...")
        print("[*] Press Ctrl+C to stop\n")
        
        iteration = 0
        try:
            while True:
                iteration += 1
                print(f"\n=== Activity Cycle #{iteration} ===")
                self.normal_activity_sequence()
                
                # Longer pause between activity cycles (30-120 seconds = user breaks)
                pause = random.uniform(30, 120)
                print(f"\n[*] Pausing for {pause:.1f} seconds before next cycle...\n")
                time.sleep(pause)
        
        except KeyboardInterrupt:
            print(f"\n\n[+] Stopped after {iteration} activity cycles")
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <jenkins_url>")
        print(f"Example: python3 {sys.argv[0]} http://localhost:8080")
        sys.exit(1)
    
    jenkins_url = sys.argv[1]
    user = JenkinsNormalUser(jenkins_url)
    user.run_infinite_loop()
