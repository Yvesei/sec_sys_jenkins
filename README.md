# SIEM + Jenkins Lab Workflow

## 1. Start the environment

```bash
docker compose up
````

Wait for **Kibana** to fully load.

---

## 2. Run detection setup

```bash
./detection.sh
```

---

## 3. Get Jenkins initial admin password

```bash
docker logs jenkins
```

Copy the initial admin password from the logs.

---

## 4. Access Jenkins

Open in browser:

```
http://localhost:8089
```

* Paste the admin password
* Install suggested plugins
* Complete setup

---

## 5. Go to Kibana

Open Kibana in your browser.

---

## 6. Launch attacks

```bash
python3 jenkins_pentester.py http://localhost:8089 /var/log/jenkins/access.log /job/test/buildHistory/ajax\?search\=
```

---

## 7. Launch normal usage simulation

```bash
python3 jenkins_normal_user.py http://localhost:8089
```

---

## 8. Access Dashboard

```
http://localhost:8089/app/dashboards
```

---

## 9. Detection Rules

In Kibana:

* Go to **Stack Management**
* Click **Saved Objects**
* Look for: `[detection]`

