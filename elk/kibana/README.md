# Kibana local workspace

The Compose stack exposes Kibana on `http://localhost:5601`. The Flask service writes normalized events to the `cybersentinel-events` index; the example Logstash pipeline writes dated indices named `cybersentinel-events-YYYY.MM.dd`.

In Kibana, create data views for both `cybersentinel-events*` patterns and select `@timestamp` as the time field. Use Discover for timelines and Lens to chart event severity, event type, source IP, and alert/risk fields. The browser dashboard inside Flask uses authenticated API data; Kibana is an optional separate analyst search surface.

The local Compose configuration disables Elasticsearch security for a loopback-only development lab. Do not expose these ports to untrusted networks or reuse this configuration in production. Production ELK must use TLS, authentication, access policies, and independently managed secrets.
