# lophiid

Lophiid is a distributed honeypot allowing many sensors to be controlled
by a single backend.

One of the ideas behind lophiid is that attacks are widespread and having
multiple sensors spread over the Internet will allow multiple opportunities to
interact with a specific attack in order to collect as much info as possible.

Key features:

- A distributed honeypot approach
- Rule based interactions with attacks
- Support both static and scripted (Javascript) response handling
- Alerting possible (Telegram, extensible)
- Comprehensive search
- Automatic tagging of requests and attacks to help triage
- Automatically collects malware
- Direct integration with VirusTotal
- Ratelimiting / DoS protection
- Exporting of rules for sharing with the community
- Extensive metrics for prometheus/grafana
- Highly customizable

Running lophiid is already very interesting and you'll collect a lot of threat
information. The project is still in an early phase of development though and
large changes are still to be expected in the near future.

# Documentation

* [Screenshots](./SCREENSHOTS.md)
* [Scripted responses](./SCRIPTING.md)
* [API cli client usage](./API_CLIENT.md)
* [UI search - overview](./SEARCH.md)
* [UI search - all keywords](./SEARCH_KEYWORDS.md)
* [Payload fetching](./PAYLOAD_FETCHING.md)
