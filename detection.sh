#!/bin/bash

##############################################################################
# Elastic Stack Detection Rules Setup Script
# Creates saved searches, visualizations, dashboards, and alerts
##############################################################################

set -e  # Exit on error

# Configuration
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
INDEX_PATTERN="jenkins-*"
SPACE="default"
DATA_VIEW_ID=""
VIZ_IDS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

##############################################################################
# Helper Functions
##############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

wait_for_kibana() {
    log_info "Waiting for Kibana to be ready..."
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -f "$KIBANA_URL/api/status" > /dev/null 2>&1; then
            if curl -s "$KIBANA_URL/api/status" | grep -q '"state":"green"'; then
                log_success "Kibana is ready!"
                return 0
            fi
        fi
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    log_error "Kibana did not become ready in time"
    exit 1
}

wait_for_elasticsearch() {
    log_info "Waiting for Elasticsearch to be ready..."
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s -f "$ELASTICSEARCH_URL/_cluster/health" > /dev/null 2>&1; then
            log_success "Elasticsearch is ready!"
            return 0
        fi
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    log_error "Elasticsearch did not become ready in time"
    exit 1
}

# Get or Create Data View and return its ID
get_data_view_id() {
    log_info "Getting/Creating data view: jenkins"
    
    # Try to find existing data view first
    local search_response=$(curl -s -X GET "$KIBANA_URL/api/data_views" \
        -H "kbn-xsrf: true" 2>/dev/null)
    
    # Extract ID if exists (looking for jenkins data view)
    local existing_id=$(echo "$search_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for dv in data.get('data_view', []):
        if dv.get('name') == 'jenkins':
            print(dv.get('id', ''))
            break
except:
    pass
" 2>/dev/null || echo "")
    
    if [ ! -z "$existing_id" ]; then
        log_success "Data view 'jenkins' exists with ID: $existing_id"
        DATA_VIEW_ID="$existing_id"
        return 0
    fi
    
    # Create new data view if not exists
    local response=$(curl -s -X POST "$KIBANA_URL/api/data_views/data_view" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
            "data_view": {
                "title": "jenkins-*",
                "name": "jenkins",
                "timeFieldName": "@timestamp"
            }
        }' 2>/dev/null)
    
    # Extract ID from response
    local new_id=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('data_view', {}).get('id', ''))
except:
    pass
" 2>/dev/null || echo "")
    
    if [ ! -z "$new_id" ]; then
        log_success "Data view 'jenkins' created with ID: $new_id"
        DATA_VIEW_ID="$new_id"
    else
        log_error "Failed to create/find data view"
        exit 1
    fi
}

# Create Saved Searches (Detection Rules)
create_saved_searches() {
    log_info "Creating saved searches for detection rules..."
    
    # Rule 1: SQL Injection Detection
    log_info "Creating: SQL Injection Detection"
    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[DETECTION] SQL Injection Attacks\",
                \"description\": \"Detects SQL injection attempts (T1190). Monitors SQLi payloads in user-agent string.\",
                \"columns\": [\"@timestamp\", \"car.src_ip\", \"car.user_agent_full\", \"car.response_status_code\", \"attack.technique\"],
                \"sort\": [[\"@timestamp\", \"desc\"]],
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"request:(union OR select OR 1=1 OR sleep OR benchmark OR waitfor)\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }" > /dev/null
    log_success "SQL Injection detection rule created"
    
    # Rule 2: XSS Detection
    log_info "Creating: XSS Detection"

    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{
        \"attributes\": {
        \"title\": \"[DETECTION] XSS Attacks\",
        \"description\": \"Detects Cross-Site Scripting attempts (T1059).\",
        \"columns\": [\"@timestamp\", \"car.src_ip\", \"car.user_agent_full\", \"attack.technique\"],
        \"sort\": [[\"@timestamp\", \"desc\"]],
        \"kibanaSavedObjectMeta\": {
            \"searchSourceJSON\": \"{
            \\\"query\\\":{
                \\\"query\\\":\\\"request:(\\\\\\\"<script\\\\\\\" OR \\\\\\\"javascript:\\\\\\\" OR \\\\\\\"onerror\\\\\\\" OR \\\\\\\"onload\\\\\\\" OR \\\\\\\"onclick\\\\\\\" OR \\\\\\\"alert\\\\\\\" OR \\\\\\\"<img\\\\\\\")\\\",
                \\\"language\\\":\\\"kuery\\\"
            },
            \\\"filter\\\":[],
            \\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"
            }\"
        }
        },
        \"references\": [{
        \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
        \"type\": \"index-pattern\",
        \"id\": \"$DATA_VIEW_ID\"
        }]
    }" > /dev/null

    log_success "XSS detection rule created"

    
    # Rule 3: Command Injection Detection
    log_info "Creating: Command Injection Detection"
    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[DETECTION] Command Injection\",
                \"description\": \"Detects command injection attempts (T1059.004). CRITICAL severity - Linux shell command patterns in user-agent.\",
                \"columns\": [\"@timestamp\", \"car.src_ip\", \"car.user_agent_full\", \"attack.technique\", \"attack.tactic\"],
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"request:(; OR | OR && OR bash OR cat OR ls OR id OR whoami)\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }" > /dev/null
    log_success "Command Injection detection rule created"
    
    # Rule 4: Path Traversal Detection
    log_info "Creating: Path Traversal Detection"
    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[DETECTION] Path Traversal\",
                \"description\": \"Detects directory traversal attempts (T1083). Monitors for path traversal patterns in user-agent on Linux systems.\",
                \"columns\": [\"@timestamp\", \"car.src_ip\", \"car.user_agent_full\", \"attack.technique\"],
                \"sort\": [[\"@timestamp\", \"desc\"]],
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"request:(../ OR %2e%2e OR /etc/passwd OR /etc/shadow OR /root/ OR /home/)\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }" > /dev/null
    log_success "Path Traversal detection rule created"
    
    # Rule 5: Jenkins Exploitation
    log_info "Creating: Jenkins Exploitation Detection"
    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[DETECTION] Jenkins Exploitation\",
                \"description\": \"Detects Jenkins-specific attacks (T1190). Monitors access to sensitive Jenkins endpoints.\",
                \"columns\": [\"@timestamp\", \"car.src_ip\", \"car.user_agent_full\", \"attack.technique\", \"scenario.id\"],
                \"sort\": [[\"@timestamp\", \"desc\"]],
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"request:(/script OR /configure OR /credentials OR /systemInfo OR /asynchPeople OR /securityRealm OR /computer/ OR /restart)\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }" > /dev/null
    log_success "Jenkins Exploitation detection rule created"
    
    # Rule 6: All Malicious Activity
    log_info "Creating: All Malicious Activity"

    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{
        \"attributes\": {
        \"title\": \"[DETECTION] All Malicious Activity\",
        \"description\": \"Overview of all detected attacks. Shows all events with suspicious patterns.\",
        \"columns\": [\"@timestamp\", \"car.src_ip\", \"request\", \"car.response_status_code\"],
        \"sort\": [[\"@timestamp\", \"desc\"]],
        \"kibanaSavedObjectMeta\": {
            \"searchSourceJSON\": \"{
            \\\"query\\\":{
                \\\"query\\\":\\\"request:(\\\\\\\"union\\\\\\\" OR \\\\\\\"select\\\\\\\" OR \\\\\\\"1=1\\\\\\\" OR \\\\\\\"sleep\\\\\\\" OR \\\\\\\"<script\\\\\\\" OR \\\\\\\"javascript:\\\\\\\" OR \\\\\\\"onerror\\\\\\\" OR \\\\\\\"../\\\\\\\" OR \\\\\\\";\\\\\\\" OR \\\\\\\"|\\\\\\\" OR \\\\\\\"&&\\\\\\\" OR \\\\\\\"bash\\\\\\\" OR \\\\\\\"cat\\\\\\\" OR \\\\\\\"/script\\\\\\\" OR \\\\\\\"/configure\\\\\\\")\\\",
                \\\"language\\\":\\\"kuery\\\"
            },
            \\\"filter\\\":[],
            \\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"
            }\"
        }
        },
        \"references\": [{
        \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
        \"type\": \"index-pattern\",
        \"id\": \"$DATA_VIEW_ID\"
        }]
    }" > /dev/null

    log_success "All Malicious Activity detection rule created"
    
    # Rule 7: Failed HTTP Requests
    log_info "Creating: Failed HTTP Requests"
    curl -s -X POST "$KIBANA_URL/api/saved_objects/search" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[DETECTION] Failed HTTP Requests\",
                \"description\": \"Monitors 403/500/502 responses which may indicate blocked attacks or exploitation attempts.\",
                \"columns\": [\"@timestamp\", \"car.src_ip\", \"car.action\", \"car.url_remainder\", \"car.response_status_code\"],
                \"sort\": [[\"@timestamp\", \"desc\"]],
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"car.response_status_code:(403 OR 500 OR 502)\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }" > /dev/null
    log_success "Failed HTTP Requests detection rule created"
    
    log_success "All saved searches created!"
}

# Create Visualizations and store their IDs
create_visualizations() {
    log_info "Creating visualizations..."
    
    # Visualization 1: Attack Type Distribution
    log_info "Creating: Attack Type Distribution"
    local viz1_response=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[VIZ] Attack Type Distribution\",
                \"description\": \"Distribution of different attack types detected\",
                \"visState\": \"{\\\"title\\\":\\\"[VIZ] Attack Type Distribution\\\",\\\"type\\\":\\\"pie\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"params\\\":{\\\"field\\\":\\\"attack_annotation.keyword\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":10},\\\"schema\\\":\\\"segment\\\"}],\\\"params\\\":{\\\"type\\\":\\\"pie\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"isDonut\\\":true}}\",
                \"uiStateJSON\": \"{}\",
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"event.label:\\\\\\\"malicious\\\\\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }")
    local viz1_id=$(echo "$viz1_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    [ ! -z "$viz1_id" ] && VIZ_IDS+=("$viz1_id") && log_success "Attack Type Distribution created (ID: $viz1_id)"
    
    # Visualization 2: Attacks Timeline
    log_info "Creating: Attacks Timeline"
    local viz2_response=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[VIZ] Attacks Timeline\",
                \"description\": \"Timeline of attacks by technique\",
                \"visState\": \"{\\\"title\\\":\\\"[VIZ] Attacks Timeline\\\",\\\"type\\\":\\\"histogram\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"date_histogram\\\",\\\"params\\\":{\\\"field\\\":\\\"@timestamp\\\",\\\"interval\\\":\\\"auto\\\",\\\"min_doc_count\\\":1},\\\"schema\\\":\\\"segment\\\"},{\\\"id\\\":\\\"3\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"params\\\":{\\\"field\\\":\\\"attack.technique.keyword\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":5},\\\"schema\\\":\\\"group\\\"}],\\\"params\\\":{\\\"type\\\":\\\"histogram\\\",\\\"grid\\\":{\\\"categoryLines\\\":false},\\\"categoryAxes\\\":[{\\\"id\\\":\\\"CategoryAxis-1\\\",\\\"type\\\":\\\"category\\\",\\\"position\\\":\\\"bottom\\\",\\\"show\\\":true,\\\"style\\\":{},\\\"scale\\\":{\\\"type\\\":\\\"linear\\\"},\\\"labels\\\":{\\\"show\\\":true,\\\"filter\\\":true,\\\"truncate\\\":100},\\\"title\\\":{}}],\\\"valueAxes\\\":[{\\\"id\\\":\\\"ValueAxis-1\\\",\\\"name\\\":\\\"LeftAxis-1\\\",\\\"type\\\":\\\"value\\\",\\\"position\\\":\\\"left\\\",\\\"show\\\":true,\\\"style\\\":{},\\\"scale\\\":{\\\"type\\\":\\\"linear\\\",\\\"mode\\\":\\\"normal\\\"},\\\"labels\\\":{\\\"show\\\":true,\\\"rotate\\\":0,\\\"filter\\\":false,\\\"truncate\\\":100},\\\"title\\\":{\\\"text\\\":\\\"Count\\\"}}],\\\"seriesParams\\\":[{\\\"show\\\":true,\\\"type\\\":\\\"histogram\\\",\\\"mode\\\":\\\"stacked\\\",\\\"data\\\":{\\\"label\\\":\\\"Count\\\",\\\"id\\\":\\\"1\\\"},\\\"valueAxis\\\":\\\"ValueAxis-1\\\",\\\"drawLinesBetweenPoints\\\":true,\\\"lineWidth\\\":2,\\\"showCircles\\\":true}],\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"times\\\":[],\\\"addTimeMarker\\\":false}}\",
                \"uiStateJSON\": \"{}\",
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"event.label:\\\\\\\"malicious\\\\\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }")
    local viz2_id=$(echo "$viz2_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    [ ! -z "$viz2_id" ] && VIZ_IDS+=("$viz2_id") && log_success "Attacks Timeline created (ID: $viz2_id)"
    
    # Visualization 3: Top Attacker IPs
    log_info "Creating: Top Attacker IPs"
    local viz3_response=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[VIZ] Top Attacker IPs\",
                \"description\": \"Top source IPs performing attacks\",
                \"visState\": \"{\\\"title\\\":\\\"[VIZ] Top Attacker IPs\\\",\\\"type\\\":\\\"table\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"params\\\":{\\\"field\\\":\\\"car.src_ip.keyword\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":10},\\\"schema\\\":\\\"bucket\\\"},{\\\"id\\\":\\\"3\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"params\\\":{\\\"field\\\":\\\"attack_annotation.keyword\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":5},\\\"schema\\\":\\\"bucket\\\"}],\\\"params\\\":{\\\"perPage\\\":10,\\\"showPartialRows\\\":false,\\\"showMetricsAtAllLevels\\\":false,\\\"sort\\\":{\\\"columnIndex\\\":null,\\\"direction\\\":null},\\\"showTotal\\\":false,\\\"totalFunc\\\":\\\"sum\\\"}}\",
                \"uiStateJSON\": \"{\\\"vis\\\":{\\\"params\\\":{\\\"sort\\\":{\\\"columnIndex\\\":2,\\\"direction\\\":\\\"desc\\\"}}}}\",
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"dataset.category:\\\\\\\"attack\\\\\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }")
    local viz3_id=$(echo "$viz3_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    [ ! -z "$viz3_id" ] && VIZ_IDS+=("$viz3_id") && log_success "Top Attacker IPs created (ID: $viz3_id)"
    
    # Visualization 4: MITRE ATT&CK Techniques
    log_info "Creating: MITRE ATT&CK Techniques"
    local viz4_response=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[VIZ] MITRE ATT&CK Techniques\",
                \"description\": \"Distribution of MITRE ATT&CK techniques observed\",
                \"visState\": \"{\\\"title\\\":\\\"[VIZ] MITRE ATT&CK Techniques\\\",\\\"type\\\":\\\"horizontal_bar\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"params\\\":{\\\"field\\\":\\\"attack.technique.keyword\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":10},\\\"schema\\\":\\\"segment\\\"}],\\\"params\\\":{\\\"type\\\":\\\"horizontal_bar\\\",\\\"grid\\\":{\\\"categoryLines\\\":false},\\\"categoryAxes\\\":[{\\\"id\\\":\\\"CategoryAxis-1\\\",\\\"type\\\":\\\"category\\\",\\\"position\\\":\\\"left\\\",\\\"show\\\":true,\\\"style\\\":{},\\\"scale\\\":{\\\"type\\\":\\\"linear\\\"},\\\"labels\\\":{\\\"show\\\":true,\\\"filter\\\":true,\\\"truncate\\\":100},\\\"title\\\":{}}],\\\"valueAxes\\\":[{\\\"id\\\":\\\"ValueAxis-1\\\",\\\"name\\\":\\\"LeftAxis-1\\\",\\\"type\\\":\\\"value\\\",\\\"position\\\":\\\"bottom\\\",\\\"show\\\":true,\\\"style\\\":{},\\\"scale\\\":{\\\"type\\\":\\\"linear\\\",\\\"mode\\\":\\\"normal\\\"},\\\"labels\\\":{\\\"show\\\":true,\\\"rotate\\\":0,\\\"filter\\\":false,\\\"truncate\\\":100},\\\"title\\\":{\\\"text\\\":\\\"Count\\\"}}],\\\"seriesParams\\\":[{\\\"show\\\":true,\\\"type\\\":\\\"histogram\\\",\\\"mode\\\":\\\"stacked\\\",\\\"data\\\":{\\\"label\\\":\\\"Count\\\",\\\"id\\\":\\\"1\\\"},\\\"valueAxis\\\":\\\"ValueAxis-1\\\",\\\"drawLinesBetweenPoints\\\":true,\\\"lineWidth\\\":2,\\\"showCircles\\\":true}],\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"times\\\":[],\\\"addTimeMarker\\\":false}}\",
                \"uiStateJSON\": \"{}\",
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"attack.technique:*\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }")
    local viz4_id=$(echo "$viz4_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    [ ! -z "$viz4_id" ] && VIZ_IDS+=("$viz4_id") && log_success "MITRE ATT&CK Techniques created (ID: $viz4_id)"
    
    # Visualization 5: Attack Success Analysis
    log_info "Creating: Attack Success Analysis"
    local viz5_response=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[VIZ] Attack Success Analysis\",
                \"description\": \"Analysis of attack outcomes based on HTTP response codes\",
                \"visState\": \"{\\\"title\\\":\\\"[VIZ] Attack Success Analysis\\\",\\\"type\\\":\\\"pie\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"params\\\":{\\\"field\\\":\\\"car.response_status_code\\\",\\\"orderBy\\\":\\\"1\\\",\\\"order\\\":\\\"desc\\\",\\\"size\\\":10},\\\"schema\\\":\\\"segment\\\"}],\\\"params\\\":{\\\"type\\\":\\\"pie\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"isDonut\\\":false}}\",
                \"uiStateJSON\": \"{}\",
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"event.label:\\\\\\\"malicious\\\\\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }")
    local viz5_id=$(echo "$viz5_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    [ ! -z "$viz5_id" ] && VIZ_IDS+=("$viz5_id") && log_success "Attack Success Analysis created (ID: $viz5_id)"
    
    # Visualization 6: Total Attacks Metric
    log_info "Creating: Total Attacks Metric"
    local viz6_response=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"[VIZ] Total Attacks\",
                \"description\": \"Total number of attacks detected\",
                \"visState\": \"{\\\"title\\\":\\\"[VIZ] Total Attacks\\\",\\\"type\\\":\\\"metric\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"}],\\\"params\\\":{\\\"addTooltip\\\":true,\\\"addLegend\\\":false,\\\"type\\\":\\\"metric\\\",\\\"metric\\\":{\\\"percentageMode\\\":false,\\\"useRanges\\\":false,\\\"colorSchema\\\":\\\"Green to Red\\\",\\\"metricColorMode\\\":\\\"None\\\",\\\"colorsRange\\\":[{\\\"from\\\":0,\\\"to\\\":10000}],\\\"labels\\\":{\\\"show\\\":true},\\\"invertColors\\\":false,\\\"style\\\":{\\\"bgFill\\\":\\\"#000\\\",\\\"bgColor\\\":false,\\\"labelColor\\\":false,\\\"subText\\\":\\\"\\\",\\\"fontSize\\\":60}}}}\",
                \"uiStateJSON\": \"{}\",
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"dataset.category:\\\\\\\"attack\\\\\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
                }
            },
            \"references\": [{
                \"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\",
                \"type\": \"index-pattern\",
                \"id\": \"$DATA_VIEW_ID\"
            }]
        }")
    local viz6_id=$(echo "$viz6_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    [ ! -z "$viz6_id" ] && VIZ_IDS+=("$viz6_id") && log_success "Total Attacks Metric created (ID: $viz6_id)"
    
    log_success "All visualizations created! (${#VIZ_IDS[@]} visualizations)"
}

# Create Dashboard with visualizations already added
create_dashboard() {
    log_info "Creating Security Monitoring Dashboard with visualizations..."
    
    if [ ${#VIZ_IDS[@]} -eq 0 ]; then
        log_warning "No visualization IDs found, creating empty dashboard"
        PANELS_JSON="[]"
    else
        log_info "Building dashboard with ${#VIZ_IDS[@]} visualizations..."
        
        # Build panels JSON with proper layout
        PANELS_JSON="["
        local panel_index=0
        local row=0
        local col=0
        
        for viz_id in "${VIZ_IDS[@]}"; do
            [ $panel_index -gt 0 ] && PANELS_JSON+=","
            
            # Layout: 2 visualizations per row
            if [ $panel_index -eq 0 ]; then
                # Total Attacks Metric - full width at top
                PANELS_JSON+="{\"version\":\"8.11.0\",\"type\":\"visualization\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":15,\"i\":\"$panel_index\"},\"panelIndex\":\"$panel_index\",\"embeddableConfig\":{},\"panelRefName\":\"panel_$panel_index\"}"
                row=15
            elif [ $panel_index -le 2 ]; then
                # Row 1: Attack Type Distribution, Attacks Timeline
                local x=$((($panel_index - 1) * 24))
                PANELS_JSON+="{\"version\":\"8.11.0\",\"type\":\"visualization\",\"gridData\":{\"x\":$x,\"y\":$row,\"w\":24,\"h\":15,\"i\":\"$panel_index\"},\"panelIndex\":\"$panel_index\",\"embeddableConfig\":{},\"panelRefName\":\"panel_$panel_index\"}"
                [ $panel_index -eq 2 ] && row=30
            else
                # Rows 2+: Other visualizations
                local x=$((($panel_index - 3) % 2 * 24))
                [ $x -eq 0 ] && [ $panel_index -gt 3 ] && row=$((row + 15))
                PANELS_JSON+="{\"version\":\"8.11.0\",\"type\":\"visualization\",\"gridData\":{\"x\":$x,\"y\":$row,\"w\":24,\"h\":15,\"i\":\"$panel_index\"},\"panelIndex\":\"$panel_index\",\"embeddableConfig\":{},\"panelRefName\":\"panel_$panel_index\"}"
            fi
            
            panel_index=$((panel_index + 1))
        done
        
        PANELS_JSON+="]"
    fi
    
    # Build references array
    REFERENCES="["
    local ref_index=0
    for viz_id in "${VIZ_IDS[@]}"; do
        [ $ref_index -gt 0 ] && REFERENCES+=","
        REFERENCES+="{\"name\":\"panel_$ref_index\",\"type\":\"visualization\",\"id\":\"$viz_id\"}"
        ref_index=$((ref_index + 1))
    done
    REFERENCES+="]"
    
    curl -s -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"title\": \"Security Monitoring Dashboard\",
                \"description\": \"Comprehensive security monitoring for detected attacks and threats\",
                \"panelsJSON\": $(echo "$PANELS_JSON" | python3 -c "import sys, json; print(json.dumps(sys.stdin.read()))"),
                \"optionsJSON\": \"{\\\"darkTheme\\\":false,\\\"useMargins\\\":true,\\\"hidePanelTitles\\\":false}\",
                \"timeRestore\": false,
                \"kibanaSavedObjectMeta\": {
                    \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[]}\"
                }
            },
            \"references\": $REFERENCES
        }" > /dev/null
    
    log_success "Dashboard created with ${#VIZ_IDS[@]} visualizations!"
}

# Main Execution
main() {
    echo ""
    echo "=========================================================================="
    echo "          Elastic Stack Detection Rules Setup Script"
    echo "=========================================================================="
    echo ""

    
    # Get data view ID
    get_data_view_id
    
    # Create detection components
    create_saved_searches
    create_visualizations
    create_dashboard
    
    echo ""
    echo "=========================================================================="
    log_success "Setup Complete!"
    echo "=========================================================================="
    echo ""
    echo "✅ Data view: jenkins (ID: $DATA_VIEW_ID)"
    echo "✅ Created 7 detection rules (saved searches)"
    echo "✅ Created ${#VIZ_IDS[@]} visualizations"
    echo "✅ Created 1 dashboard with all visualizations"
    echo ""
    echo "🌐 Next Steps:"
    echo "   1. Open Kibana: http://localhost:5601"
    echo "   2. Go to: Dashboard → 'Security Monitoring Dashboard'"
    echo "   3. All visualizations are already added!"
    echo ""
    echo "📊 To view detection rules:"
    echo "   Kibana → Discover → Open → Filter '[DETECTION]'"
    echo ""
    echo "=========================================================================="
}

# Run main function
main "$@"